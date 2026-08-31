// Ticketed media generation: image and text-to-speech over AnonRouter's
// two-origin privacy split.
//
// THE WHOLE POINT OF THIS FILE. A media request is split across two hosts that
// are deliberately told different things:
//
//   control origin    sees the API key and the content-free shape of the work
//                     (operation, model, image size/format, speech character
//                     COUNT, voice, container). It mints a single-use ticket.
//                     It never sees the prompt or the input text.
//   inference origin  sees the prompt or the input text, authenticated by that
//                     opaque single-use ticket ALONE. It never sees the API
//                     key, a cookie, or any stable account identifier.
//
// Neither host holds both halves, so neither can by itself say "this account
// asked for this picture". That property is not a side effect of how the
// requests happen to be written: it is the reason there are two of them, and
// every function here is arranged so that breaking it requires deleting a test.
//
// An official OpenAI client cannot perform this exchange. It has one base URL
// and one credential, so it would send the API key and the prompt to the same
// host in one request. See `docs/` and the package README: the compatibility
// broker is a DIFFERENT, lower-privacy mode and is never selected implicitly.
//
// THE CONTRACT IS DERIVED FROM DEPLOYED CODE, not from documentation. Every
// field, bound fact, and rejection below matches src/routes/image.ts,
// src/routes/speech.ts, src/inference/ticketRequestSchema.ts and
// src/providers/types.ts in the AnonRouter production tree, verified against
// the live origins on 2026-08-30.

import { base64ToBytes, isCanonicalBase64 } from "./bytes.js";
import { ConfidentialError } from "./errors.js";
import { joinUrl, type FetchLike } from "./transport/types.js";

// ---- Canonical bounds, mirrored from the server ------------------------------
//
// These are duplicated from AnonRouter's `src/providers/types.ts` so a request
// that cannot possibly succeed is refused BEFORE a ticket is minted. Minting
// first and failing at the relay would burn a single-use ticket for nothing.

/** `parseImageSize` bounds. A dimension outside these is a 400 at every surface. */
export const IMAGE_MIN_DIMENSION = 128;
export const IMAGE_MAX_DIMENSION = 2048;
export const IMAGE_DEFAULT_SIZE = "1024x1024";
/** The only image container AnonRouter serves. The ticket binds it. */
export const IMAGE_RESPONSE_FORMAT = "b64_json";
/** The priced unit ceiling for speech: the ticket binds the exact count. */
export const SPEECH_MAX_INPUT_CHARS = 20_000;
export const SPEECH_MAX_VOICE_CHARS = 64;
/** The only speech container AnonRouter serves. The ticket binds it. */
export const SPEECH_RESPONSE_FORMAT = "mp3";
/** `imageGenerationRequestSchema` prompt bound. */
export const IMAGE_MAX_PROMPT_CHARS = 10_000;

const TICKET_HEADER = "x-anonrouter-ticket";
const IMAGE_PATH = "/v1/images/generations";
const SPEECH_PATH = "/v1/audio/speech";
const TICKET_PATH = "/v1/inference/tickets";

/** Production defaults. The two origins are different hosts on purpose. */
export const DEFAULT_CONTROL_ORIGIN = "https://api.anonrouter.ai";
export const DEFAULT_INFERENCE_ORIGIN = "https://api.private.anonrouter.ai";

// ---- Public request types ----------------------------------------------------
//
// Parameter names are OpenAI's, so a developer moving from `openai` or
// OpenRouter writes the same object. Where AnonRouter does not support an
// OpenAI parameter it is REJECTED rather than dropped: silently ignoring `n: 4`
// would hand back one image and charge for one while the caller believed they
// asked for four.

export interface ImageGenerateInput {
  model: string;
  /** The prompt. Sent ONLY to the inference origin. Never minted, never logged. */
  prompt: string;
  /** "WIDTHxHEIGHT", 128..2048 per side. Defaults to 1024x1024. */
  size?: string;
  /** Only "b64_json" is served. Present so an OpenAI-shaped call type-checks. */
  response_format?: typeof IMAGE_RESPONSE_FORMAT;
  /** OpenAI's image count. AnonRouter serves exactly one; only `1` is accepted. */
  n?: number;
  signal?: AbortSignal;
}

export interface SpeechCreateInput {
  model: string;
  /** The text to speak. Sent ONLY to the inference origin; the control origin
   *  is told its LENGTH and nothing else, because length is the priced unit. */
  input: string;
  /** Provider voice id. Bound into the ticket; omit to bind "no voice". */
  voice?: string;
  /** Only "mp3" is served. Present so an OpenAI-shaped call type-checks. */
  response_format?: typeof SPEECH_RESPONSE_FORMAT;
  /** OpenAI's playback rate. AnonRouter does not serve it; only `1` is accepted. */
  speed?: number;
  signal?: AbortSignal;
}

// ---- Public result types -----------------------------------------------------

/**
 * Response metadata worth keeping. These come from headers the relay sets and
 * are how a caller reconciles a generation with their billing: `selected_model`
 * is the exact provider route that ran, `request_id` is the id that appears in
 * the ledger.
 */
export interface MediaResponseMetadata {
  /** `x-anonrouter-selected-model`: "provider/model" actually routed to. */
  selected_model?: string;
  /** `x-anonrouter-routing`: how the model was chosen ("exact"). */
  routing?: string;
  /** The gateway request id, when the deployment reports one. */
  request_id?: string;
  /** Rate-limit state after this call, when the relay reported it. */
  rate_limit?: MediaRateLimit;
}

export interface MediaRateLimit {
  limit_requests?: number;
  remaining_requests?: number;
  reset_requests?: number;
  limit_tokens?: number;
  remaining_tokens?: number;
  reset_tokens?: number;
}

export interface GeneratedImage {
  /** Base64 image bytes, exactly as the provider returned them. */
  b64_json: string;
  /** The concrete media type, e.g. "image/png". Needed to save or render. */
  mime_type: string;
  /** The decoded bytes, for callers that want to write a file directly. */
  bytes: Uint8Array;
}

export interface ImageGenerateResult extends MediaResponseMetadata {
  created: number;
  /** The public model id the gateway reports for the generation. */
  model: string;
  data: GeneratedImage[];
  /** Provider reported the image was blurred by its safety layer. */
  provider_blurred?: boolean;
  /** Provider reported a content-policy violation for the prompt. */
  provider_content_violation?: boolean;
}

export interface SpeechCreateResult extends MediaResponseMetadata {
  /** The audio bytes. The endpoint returns one complete buffer, not a stream. */
  audio: Uint8Array;
  /** The concrete media type from the response, e.g. "audio/mpeg". */
  content_type: string;
}

// ---- Diagnostics -------------------------------------------------------------

/**
 * Header names whose VALUES are credentials or capabilities. A diagnostic that
 * echoed one of these would turn a debugging aid into a credential leak: an
 * `authorization` value is the API key itself, and an `x-anonrouter-ticket` is
 * a bearer capability for a paid generation until it is redeemed.
 */
const REDACTED_HEADERS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "proxy-authorization",
  TICKET_HEADER
]);

/**
 * Replace every sensitive header value with a fixed marker, preserving the
 * NAMES so a caller can still see which headers a request carried. Exported
 * because the same rule must apply to anything anyone else logs about a media
 * call.
 */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    out[name] = REDACTED_HEADERS.has(name.toLowerCase()) ? "<redacted>" : value;
  }
  return out;
}

/**
 * What a failed media call reports. Deliberately carries NO body: an error body
 * from the relay could quote the prompt back, and a prompt in an exception is a
 * prompt in a log aggregator.
 */
export interface MediaErrorDiagnostics {
  /** The origin the failing request went to, so a misconfiguration is visible. */
  origin: string;
  path: string;
  status?: number;
  /** The gateway's error `type`, when it sent one. Machine-readable, content-free. */
  error_type?: string;
  request_id?: string;
  /** The request headers, with every credential value replaced. */
  headers: Record<string, string>;
}

/** A media failure with a machine-readable code and redacted diagnostics. */
export class MediaError extends ConfidentialError {
  readonly diagnostics: MediaErrorDiagnostics;

  constructor(
    code: ConfidentialError["code"],
    message: string,
    diagnostics: MediaErrorDiagnostics
  ) {
    super(code, message);
    this.name = "MediaError";
    this.diagnostics = diagnostics;
  }
}

// ---- Validation --------------------------------------------------------------

/**
 * The number of UTF-16 code units in a string.
 *
 * THIS IS THE PRICED UNIT AND IT MUST MATCH THE SERVER EXACTLY. AnonRouter runs
 * on Node, where `input.length` and zod's `.max()` both count UTF-16 code units,
 * and the relay rejects a body whose length differs from the ticket by even one
 * (`ticket_input_length_mismatch`). In JavaScript this is just `.length`; it is
 * named because the Python port CANNOT use `len()`, which counts code points and
 * disagrees on every emoji and every astral-plane character.
 */
export function utf16Length(text: string): number {
  return text.length;
}

function reject(message: string): never {
  throw new ConfidentialError("unsupported_request", message);
}

/**
 * Refuse any key the caller did not mean to send.
 *
 * The server schemas are `.strict()`. Accepting `quality: "hd"` here and
 * dropping it would produce a standard-resolution image for a caller who
 * believes they paid for HD, which is worse than an error.
 */
function rejectUnknownKeys(input: object, allowed: readonly string[], what: string): void {
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) {
      reject(
        `${what} does not support "${key}". AnonRouter's media contract is strict; `
        + `supported keys are: ${allowed.join(", ")}.`
      );
    }
  }
}

function requireModel(model: unknown): string {
  if (typeof model !== "string" || model.length === 0 || model.length > 256) {
    reject("model must be a non-empty string of at most 256 characters.");
  }
  return model;
}

/**
 * Canonicalize "WIDTHxHEIGHT" to the exact form the ticket mint echoes back.
 *
 * The mint re-emits the size as `${width}x${height}` from parsed integers, so a
 * caller who writes "0512x0512" (which the server's regex accepts) would get
 * "512x512" back and a naive string comparison of the echo would report drift
 * that is not there. Canonicalizing here means the SAME string goes to both
 * hosts and the echo check is exact.
 */
export function canonicalImageSize(size: string): string {
  if (!/^\d{3,4}x\d{3,4}$/.test(size)) {
    reject('size must look like "1024x1024" (three or four digits per side).');
  }
  const [width, height] = size.split("x").map((part) => Number(part));
  if (
    !Number.isInteger(width) || !Number.isInteger(height)
    || width < IMAGE_MIN_DIMENSION || height < IMAGE_MIN_DIMENSION
    || width > IMAGE_MAX_DIMENSION || height > IMAGE_MAX_DIMENSION
  ) {
    reject(
      `size must be between ${IMAGE_MIN_DIMENSION}x${IMAGE_MIN_DIMENSION} `
      + `and ${IMAGE_MAX_DIMENSION}x${IMAGE_MAX_DIMENSION}.`
    );
  }
  return `${width}x${height}`;
}

const IMAGE_KEYS = ["model", "prompt", "size", "response_format", "n", "signal"] as const;
const SPEECH_KEYS = ["model", "input", "voice", "response_format", "speed", "signal"] as const;

/** A validated image request, split into what each host is allowed to learn. */
interface NormalizedImage {
  model: string;
  prompt: string;
  size: string;
  response_format: typeof IMAGE_RESPONSE_FORMAT;
}

function normalizeImage(input: ImageGenerateInput): NormalizedImage {
  if (!input || typeof input !== "object") reject("images.generate needs a request object.");
  rejectUnknownKeys(input, IMAGE_KEYS, "images.generate");
  const model = requireModel(input.model);
  if (typeof input.prompt !== "string" || input.prompt.length === 0) {
    reject("prompt must be a non-empty string.");
  }
  if (utf16Length(input.prompt) > IMAGE_MAX_PROMPT_CHARS) {
    reject(`prompt must be at most ${IMAGE_MAX_PROMPT_CHARS} characters.`);
  }
  if (input.response_format !== undefined && input.response_format !== IMAGE_RESPONSE_FORMAT) {
    reject(`AnonRouter serves image generation only as ${IMAGE_RESPONSE_FORMAT}.`);
  }
  // `n` exists so an OpenAI-shaped call is accepted verbatim, but AnonRouter
  // prices and returns exactly one image and the ticket authorizes exactly one
  // flat unit. Anything else must be an error, never a silent single image.
  if (input.n !== undefined && input.n !== 1) {
    reject(
      "AnonRouter generates one image per request; n must be 1 or omitted. "
      + "Issue separate calls to generate more, so each is ticketed and priced on its own."
    );
  }
  return {
    model,
    prompt: input.prompt,
    size: canonicalImageSize(input.size ?? IMAGE_DEFAULT_SIZE),
    response_format: IMAGE_RESPONSE_FORMAT
  };
}

interface NormalizedSpeech {
  model: string;
  input: string;
  /** UTF-16 code units. The exact number the ticket binds. */
  input_chars: number;
  voice?: string;
  response_format: typeof SPEECH_RESPONSE_FORMAT;
}

function normalizeSpeech(input: SpeechCreateInput): NormalizedSpeech {
  if (!input || typeof input !== "object") reject("audio.speech.create needs a request object.");
  rejectUnknownKeys(input, SPEECH_KEYS, "audio.speech.create");
  const model = requireModel(input.model);
  if (typeof input.input !== "string" || input.input.length === 0) {
    reject("input must be a non-empty string.");
  }
  const inputChars = utf16Length(input.input);
  if (inputChars > SPEECH_MAX_INPUT_CHARS) {
    reject(`input must be at most ${SPEECH_MAX_INPUT_CHARS} characters.`);
  }
  if (input.voice !== undefined) {
    if (typeof input.voice !== "string" || input.voice.length === 0) {
      reject("voice must be a non-empty string when supplied.");
    }
    if (utf16Length(input.voice) > SPEECH_MAX_VOICE_CHARS) {
      reject(`voice must be at most ${SPEECH_MAX_VOICE_CHARS} characters.`);
    }
  }
  if (input.response_format !== undefined && input.response_format !== SPEECH_RESPONSE_FORMAT) {
    reject(`AnonRouter serves speech only as ${SPEECH_RESPONSE_FORMAT}.`);
  }
  // Speech is priced per character for a fixed rendering; a playback rate is not
  // part of the authorized work, so accepting and dropping it would return audio
  // at a speed the caller did not ask for.
  if (input.speed !== undefined && input.speed !== 1) {
    reject("AnonRouter does not support a speech speed parameter; speed must be 1 or omitted.");
  }
  return {
    model,
    input: input.input,
    input_chars: inputChars,
    ...(input.voice !== undefined ? { voice: input.voice } : {}),
    response_format: SPEECH_RESPONSE_FORMAT
  };
}

// ---- The ticket the control origin issues ------------------------------------

/** The subset of the mint response this SDK checks. Extra fields are ignored. */
interface IssuedTicket {
  ticket?: unknown;
  operation?: unknown;
  model?: unknown;
  size?: unknown;
  response_format?: unknown;
  input_chars?: unknown;
  voice?: unknown;
  expires_in?: unknown;
}

/**
 * Every fact the relay will independently re-check, checked here FIRST.
 *
 * The relay compares the redeeming body against the ticket's bound constraints
 * and answers 409 on any drift (`ticket_model_mismatch`, `ticket_size_mismatch`,
 * `ticket_format_mismatch`, `ticket_input_length_mismatch`,
 * `ticket_voice_mismatch`, `ticket_operation_mismatch`). Checking the mint's
 * echo here means a mismatch is caught BEFORE the prompt is sent anywhere: the
 * request fails on the content-free half of the exchange, and the text never
 * leaves the process. A ticket that does not bind what we asked for is not a
 * ticket we are willing to spend content on.
 */
function assertTicketBinding(
  issued: IssuedTicket,
  expected: Record<string, string | number | undefined>,
  diagnostics: MediaErrorDiagnostics
): string {
  if (typeof issued.ticket !== "string" || issued.ticket.length === 0) {
    throw new MediaError(
      "media_ticket_failed",
      "The control origin did not return a usable single-use ticket.",
      diagnostics
    );
  }
  for (const [field, want] of Object.entries(expected)) {
    if (want === undefined) {
      // "No voice" is a real bound value: the relay compares
      // `(constraints.speechVoice ?? null) !== (body.voice ?? null)`, so a
      // ticket that came back carrying a voice we did not ask for would be
      // redeemed against a body with none, and answer 409.
      if (issued[field as keyof IssuedTicket] !== undefined) {
        throw new MediaError(
          "ticket_binding_mismatch",
          `The issued ticket bound a ${field} that was not requested; refusing to send content against it.`,
          diagnostics
        );
      }
      continue;
    }
    const got = issued[field as keyof IssuedTicket];
    // The mint echoes the bound value; a missing echo is an older gateway, not
    // proof of drift, so only a PRESENT and DIFFERENT value is a mismatch.
    if (got !== undefined && got !== want) {
      throw new MediaError(
        "ticket_binding_mismatch",
        `The issued ticket bound a different ${field} than was requested; refusing to send content against it.`,
        diagnostics
      );
    }
  }
  return issued.ticket;
}

// ---- HTTP plumbing -----------------------------------------------------------

export interface MediaHttp {
  controlOrigin: string;
  inferenceOrigin: string;
  apiKey: string;
  fetchImpl: FetchLike;
}

interface ErrorEnvelope {
  error?: { type?: unknown; message?: unknown; request_id?: unknown };
}

/**
 * Map a relay/control status onto a code a caller can branch on.
 *
 * The distinction that matters for money: `ticket_rejected` and
 * `relay_refused` mean nothing was generated and nothing was charged, while
 * `provider_failed` means the request reached a provider and may have.
 */
function codeForStatus(status: number, errorType: string | undefined): ConfidentialError["code"] {
  if (status === 401) {
    // The relay answers 401 both for a missing ticket and for one already spent
    // or expired. `invalid_ticket` is specifically "you had a ticket and it is
    // no longer good", which is the replay/expiry case a caller retries by
    // starting over, not by resending.
    return errorType === "invalid_ticket" ? "ticket_rejected" : "relay_refused";
  }
  if (status === 409) return "ticket_rejected";
  if (status === 403 || status === 404 || status === 503) return "relay_refused";
  if (status === 402 || status === 429) return "relay_refused";
  if (status >= 500) return "provider_failed";
  return "relay_refused";
}

/** Read the gateway's content-free error envelope. The body is never surfaced. */
async function readErrorEnvelope(response: Response): Promise<{ type?: string; requestId?: string }> {
  try {
    const body = (await response.json()) as ErrorEnvelope;
    return {
      type: typeof body.error?.type === "string" ? body.error.type : undefined,
      requestId: typeof body.error?.request_id === "string" ? body.error.request_id : undefined
    };
  } catch {
    return {};
  }
}

/**
 * Distinguish a caller's cancellation from a deadline that expired.
 *
 * They are different events for a caller holding a paid operation: `cancelled`
 * means the caller stopped waiting deliberately, `timeout` means the deadline
 * passed with the request possibly still running upstream. Neither may be
 * retried automatically. Returns null when the failure was neither.
 */
function abortKind(error: unknown, signal?: AbortSignal): "cancelled" | "timeout" | null {
  if (error instanceof Error && error.name === "TimeoutError") return "timeout";
  if (signal?.aborted) return "cancelled";
  if (error instanceof Error && error.name === "AbortError") return "cancelled";
  return null;
}

/**
 * STEP 1. Exchange the API key for a single-use, operation-scoped ticket.
 *
 * `payload` is built by the caller from normalized input and is CONTENT-FREE by
 * construction: the image path passes model/size/format, the speech path passes
 * model/character-count/voice/format. Neither passes the prompt or the text.
 * There is no code path here that could: this function never sees them.
 */
async function mintTicket(
  http: MediaHttp,
  payload: Record<string, unknown>,
  expected: Record<string, string | number | undefined>,
  signal?: AbortSignal
): Promise<string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: `Bearer ${http.apiKey}`
  };
  const diagnostics: MediaErrorDiagnostics = {
    origin: http.controlOrigin,
    path: TICKET_PATH,
    headers: redactHeaders(headers)
  };

  let response: Response;
  try {
    response = await http.fetchImpl(joinUrl(http.controlOrigin, TICKET_PATH), {
      method: "POST",
      // The ticket mint is the ONLY request that carries the API key. It is sent
      // with `credentials: omit` regardless, so an ambient browser cookie cannot
      // silently add a second identity to it.
      credentials: "omit",
      cache: "no-store",
      headers,
      body: JSON.stringify(payload),
      signal
    });
  } catch (cause) {
    const aborted = abortKind(cause, signal);
    if (aborted) {
      throw new MediaError(aborted, `The media request ${aborted === "timeout" ? "timed out" : "was cancelled"}.`, diagnostics);
    }
    throw new MediaError("media_ticket_failed", "Could not reach the AnonRouter control origin.", diagnostics);
  }

  if (!response.ok) {
    const { type, requestId } = await readErrorEnvelope(response);
    throw new MediaError(
      "media_ticket_failed",
      `The control origin refused to mint a media ticket (HTTP ${response.status}${type ? `, ${type}` : ""}).`,
      { ...diagnostics, status: response.status, error_type: type, request_id: requestId }
    );
  }

  let issued: IssuedTicket;
  try {
    issued = (await response.json()) as IssuedTicket;
  } catch {
    throw new MediaError("media_ticket_failed", "The control origin returned an unreadable ticket response.", diagnostics);
  }
  if (!issued || typeof issued !== "object") {
    throw new MediaError("media_ticket_failed", "The control origin returned an unreadable ticket response.", diagnostics);
  }
  return assertTicketBinding(issued, expected, diagnostics);
}

/**
 * STEP 2. Send the content to the inference origin with the ticket as the only
 * credential.
 *
 * EXACTLY ONE POST. There is no retry loop here and there must never be one: a
 * media generation is billed on the provider attempt, so a transparently
 * retried POST would be a second charge for a caller who made one call. A
 * failure is reported, not repeated.
 */
async function postContent(
  http: MediaHttp,
  path: string,
  ticket: string,
  body: Record<string, unknown>,
  accept: string,
  signal?: AbortSignal
): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept,
    [TICKET_HEADER]: ticket
  };
  const diagnostics: MediaErrorDiagnostics = {
    origin: http.inferenceOrigin,
    path,
    headers: redactHeaders(headers)
  };

  let response: Response;
  try {
    response = await http.fetchImpl(joinUrl(http.inferenceOrigin, path), {
      method: "POST",
      // NO API KEY, NO COOKIE. `credentials: "omit"` also stops a browser from
      // attaching one. The single-use ticket is the entire authorization.
      credentials: "omit",
      cache: "no-store",
      headers,
      body: JSON.stringify(body),
      signal
    });
  } catch (cause) {
    const aborted = abortKind(cause, signal);
    if (aborted) {
      throw new MediaError(aborted, `The media request ${aborted === "timeout" ? "timed out" : "was cancelled"}.`, diagnostics);
    }
    // The request may or may not have reached the provider, so this is NOT
    // retried and NOT reported as a clean refusal.
    throw new MediaError("transport_failed", "Could not reach the AnonRouter inference origin.", diagnostics);
  }

  if (!response.ok) {
    const { type, requestId } = await readErrorEnvelope(response);
    throw new MediaError(
      codeForStatus(response.status, type),
      `The inference origin refused the media request (HTTP ${response.status}${type ? `, ${type}` : ""}).`,
      { ...diagnostics, status: response.status, error_type: type, request_id: requestId }
    );
  }
  return response;
}

// ---- Response parsing --------------------------------------------------------

function numberHeader(response: Response, name: string): number | undefined {
  const raw = response.headers.get(name);
  if (raw === null) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) ? value : undefined;
}

function rateLimitFrom(response: Response): MediaRateLimit | undefined {
  const rate: MediaRateLimit = {
    limit_requests: numberHeader(response, "x-ratelimit-limit-requests"),
    remaining_requests: numberHeader(response, "x-ratelimit-remaining-requests"),
    reset_requests: numberHeader(response, "x-ratelimit-reset-requests"),
    limit_tokens: numberHeader(response, "x-ratelimit-limit-tokens"),
    remaining_tokens: numberHeader(response, "x-ratelimit-remaining-tokens"),
    reset_tokens: numberHeader(response, "x-ratelimit-reset-tokens")
  };
  return Object.values(rate).some((v) => v !== undefined) ? rate : undefined;
}

function metadataFrom(response: Response): MediaResponseMetadata {
  const selected = response.headers.get("x-anonrouter-selected-model");
  const routing = response.headers.get("x-anonrouter-routing");
  const requestId = response.headers.get("x-request-id") ?? response.headers.get("x-anonrouter-request-id");
  const rate = rateLimitFrom(response);
  return {
    ...(selected ? { selected_model: selected } : {}),
    ...(routing ? { routing } : {}),
    ...(requestId ? { request_id: requestId } : {}),
    ...(rate ? { rate_limit: rate } : {})
  };
}

function boolHeader(response: Response, name: string): boolean | undefined {
  const raw = response.headers.get(name);
  if (raw === null) return undefined;
  return raw === "true";
}

function invalidImage(message: string, diagnostics: MediaErrorDiagnostics): never {
  throw new MediaError("response_invalid", message, diagnostics);
}

/**
 * Parse and VALIDATE the image envelope.
 *
 * A malformed payload is refused rather than passed through. A caller who is
 * handed an object with an empty or non-base64 `b64_json` will write a corrupt
 * file and discover it much later; failing here, with the generation already
 * paid for, at least names the problem accurately.
 */
function parseImageResponse(
  body: unknown,
  response: Response,
  diagnostics: MediaErrorDiagnostics
): ImageGenerateResult {
  if (!body || typeof body !== "object") invalidImage("The image response was not a JSON object.", diagnostics);
  const envelope = body as { created?: unknown; model?: unknown; data?: unknown };
  if (!Array.isArray(envelope.data) || envelope.data.length === 0) {
    invalidImage("The image response contained no image data.", diagnostics);
  }
  const data: GeneratedImage[] = envelope.data.map((entry) => {
    if (!entry || typeof entry !== "object") invalidImage("An image entry was not an object.", diagnostics);
    const item = entry as { b64_json?: unknown; mime_type?: unknown };
    if (typeof item.b64_json !== "string" || item.b64_json.length === 0) {
      invalidImage("An image entry carried no base64 image data.", diagnostics);
    }
    if (!isCanonicalBase64(item.b64_json)) {
      invalidImage("An image entry carried data that is not canonical base64.", diagnostics);
    }
    if (typeof item.mime_type !== "string" || !item.mime_type.startsWith("image/")) {
      invalidImage("An image entry carried no image media type.", diagnostics);
    }
    let bytes: Uint8Array;
    try {
      bytes = base64ToBytes(item.b64_json);
    } catch {
      invalidImage("An image entry carried base64 that could not be decoded.", diagnostics);
    }
    if (bytes.length === 0) invalidImage("An image entry decoded to zero bytes.", diagnostics);
    return { b64_json: item.b64_json, mime_type: item.mime_type, bytes };
  });

  const blurred = boolHeader(response, "x-anonrouter-provider-blurred");
  const violation = boolHeader(response, "x-anonrouter-provider-content-violation");
  return {
    created: typeof envelope.created === "number" ? envelope.created : Math.floor(Date.now() / 1000),
    model: typeof envelope.model === "string" ? envelope.model : "",
    data,
    ...(blurred !== undefined ? { provider_blurred: blurred } : {}),
    ...(violation !== undefined ? { provider_content_violation: violation } : {}),
    ...metadataFrom(response)
  };
}

// ---- The public surface ------------------------------------------------------

export interface ImagesApi {
  /**
   * Generate one image over the two-origin ticketed exchange.
   *
   * The prompt goes only to the inference origin; the control origin learns the
   * model, size, and format and mints a single-use ticket for exactly that work.
   */
  generate(input: ImageGenerateInput): Promise<ImageGenerateResult>;
}

export interface SpeechApi {
  /**
   * Synthesize speech over the two-origin ticketed exchange.
   *
   * The text goes only to the inference origin; the control origin learns its
   * character COUNT (the priced unit), the model, voice, and container.
   */
  create(input: SpeechCreateInput): Promise<SpeechCreateResult>;
}

export interface AudioApi {
  speech: SpeechApi;
}

/** Build the media surface over a validated two-origin HTTP context. */
export function createMediaApi(http: MediaHttp): { images: ImagesApi; audio: AudioApi } {
  async function generate(input: ImageGenerateInput): Promise<ImageGenerateResult> {
    const request = normalizeImage(input);
    // CONTENT-FREE. `prompt` is deliberately absent and must stay absent.
    const ticket = await mintTicket(
      http,
      {
        operation: "image",
        model: request.model,
        size: request.size,
        response_format: request.response_format
      },
      { operation: "image", model: request.model, size: request.size, response_format: request.response_format },
      input.signal
    );

    const response = await postContent(
      http,
      IMAGE_PATH,
      ticket,
      {
        model: request.model,
        prompt: request.prompt,
        size: request.size,
        response_format: request.response_format
      },
      "application/json",
      input.signal
    );

    const diagnostics: MediaErrorDiagnostics = {
      origin: http.inferenceOrigin,
      path: IMAGE_PATH,
      status: response.status,
      headers: redactHeaders({ "content-type": "application/json", [TICKET_HEADER]: ticket })
    };
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new MediaError("response_invalid", "The image response could not be parsed as JSON.", diagnostics);
    }
    return parseImageResponse(body, response, diagnostics);
  }

  async function create(input: SpeechCreateInput): Promise<SpeechCreateResult> {
    const request = normalizeSpeech(input);
    // CONTENT-FREE. `input_chars` is a COUNT; the text itself never appears here.
    const ticket = await mintTicket(
      http,
      {
        operation: "speech",
        model: request.model,
        input_chars: request.input_chars,
        response_format: request.response_format,
        ...(request.voice !== undefined ? { voice: request.voice } : {})
      },
      {
        operation: "speech",
        model: request.model,
        input_chars: request.input_chars,
        response_format: request.response_format,
        voice: request.voice
      },
      input.signal
    );

    const response = await postContent(
      http,
      SPEECH_PATH,
      ticket,
      {
        model: request.model,
        input: request.input,
        response_format: request.response_format,
        ...(request.voice !== undefined ? { voice: request.voice } : {})
      },
      "audio/mpeg",
      input.signal
    );

    const diagnostics: MediaErrorDiagnostics = {
      origin: http.inferenceOrigin,
      path: SPEECH_PATH,
      status: response.status,
      headers: redactHeaders({ "content-type": "application/json", [TICKET_HEADER]: ticket })
    };
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.startsWith("audio/")) {
      throw new MediaError(
        "response_invalid",
        `The speech response was not audio (content-type: ${contentType || "absent"}).`,
        diagnostics
      );
    }
    let audio: Uint8Array;
    try {
      audio = new Uint8Array(await response.arrayBuffer());
    } catch {
      throw new MediaError("response_invalid", "The speech response body could not be read.", diagnostics);
    }
    if (audio.length === 0) {
      throw new MediaError("response_invalid", "The speech response carried no audio bytes.", diagnostics);
    }
    return { audio, content_type: contentType, ...metadataFrom(response) };
  }

  return { images: { generate }, audio: { speech: { create } } };
}
