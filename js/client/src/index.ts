/**
 * @anonrouter/client
 *
 * A thin, dependency-free client for AnonRouter's public API. It targets the
 * plaintext, TEE, and private routes and speaks the OpenAI-style chat surface
 * over AnonRouter's two-request ticketed flow.
 *
 * This is NOT the confidential client. It sends your prompt as PLAINTEXT, so
 * AnonRouter's relay software handles it in order to route and meter it. On the
 * production confidential origin that relay runs inside an attested Intel TDX
 * CVM, so the plaintext does not reach ordinary AnonRouter infrastructure — but
 * this package neither verifies that nor encrypts anything, so nothing here
 * proves it to you.
 *
 * If you need to check that claim rather than take it, or to keep content opaque
 * to AnonRouter's build entirely, use @anonrouter/confidential: it verifies the
 * plane you are talking to, and its E2EE routes encrypt to the provider's
 * attested key so the relay only ever holds ciphertext.
 *
 * The one thing this client does enforce for you: the stable API key is sent
 * only on the control-plane ticket request, never on the request that carries
 * content. Content is presented to the relay with a single-use ticket and no
 * account credential attached.
 */

/** A fetch implementation. Defaults to the global fetch when omitted. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ClientOptions {
  /**
   * AnonRouter API origin, e.g. "https://api.anonrouter.ai". A trailing slash is
   * tolerated. Paths like /v1/models are appended by the client.
   *
   * Custom origins serve both roles unless `controlBaseUrl` is set. The two
   * production content names automatically use AnonRouter's separate production
   * control origin, so `baseUrl: "https://api.anonrouter.ai"` is safe by default.
   */
  baseUrl?: string;
  /**
   * Identity and billing origin: model listing and ticket issuance. This is the
   * ONLY origin the API key is sent to. Defaults to `baseUrl` for custom
   * deployments and to AnonRouter's control origin for production content names.
   */
  controlBaseUrl?: string;
  /**
   * The origin that receives request CONTENT, authenticated by the single-use
   * ticket alone. Defaults to `baseUrl`, and to AnonRouter's production
   * confidential origin when no origin is configured at all.
   *
   * Setting this to a different host from `controlBaseUrl` is what makes the
   * split real: the host that sees your prompt then never sees your API key.
   */
  inferenceBaseUrl?: string;
  /**
   * Workspace API key. Sent as a Bearer credential on control-plane requests
   * only (model listing, ticket issuance). It is never attached to the request
   * that carries content.
   */
  apiKey: string;
  /** Optional fetch override (for tests, proxies, or non-global runtimes). */
  fetch?: FetchLike;
}

/** AnonRouter's production origins. The two are different hosts on purpose. */
export const DEFAULT_CONTROL_ORIGIN = "https://control.anonrouter.ai";
export const DEFAULT_INFERENCE_ORIGIN = "https://api.anonrouter.ai";
const PRODUCTION_INFERENCE_ORIGINS = new Set([
  DEFAULT_INFERENCE_ORIGIN,
  "https://api.private.anonrouter.ai"
]);

/** The {object, data} list envelope AnonRouter returns for collections. */
export interface ListResponse<T> {
  object: "list";
  data: T[];
}

/**
 * A model as returned by GET /v1/models. Fields mirror the public gateway shape.
 * Additional fields may be present on newer gateways and are preserved verbatim.
 */
/**
 * One provider's route to a model, as the catalog publishes it.
 *
 * THIS IS THE ROW THAT MATTERS for anything privacy-related. A `ModelInfo`
 * carries a top-level `privacy_class` describing its BEST route, so a consumer
 * that reads only that will both miss a confidential route on a model whose
 * headline is `private`, and claim one for a provider that serves the same model
 * plainly. The same model id is regularly `tee` at one provider, `e2ee` at a
 * second and `private` at a third.
 *
 * Enumerate these to answer "which routes can I verify?" rather than keeping a
 * list of provider names in your own code: a written-down list is wrong the next
 * time a row moves, and silently so in both directions.
 */
export interface ProviderRoute {
  provider: string;
  provider_name?: string;
  /** `plain`, `anonymous`, `private`, `tee` or `e2ee`. */
  privacy_class: string;
  provider_privacy_class?: string;
  /** Whether this exact route can be called right now. */
  callable?: boolean;
  context_window?: number;
  max_output_tokens?: number | null;
  pricing?: {
    input_usd_per_million_tokens: number;
    output_usd_per_million_tokens: number;
    unit_usd?: number | null;
  };
}

export interface ModelInfo {
  id: string;
  object: "model";
  created: number;
  owned_by: string;
  display_name?: string;
  provider: string;
  /** `embedding` is served too, and is the only modality on some TEE routes. */
  model_type?: "text" | "image" | "tts" | "embedding";
  /** The model's BEST route's class. Per-route classes are in `provider_routes`. */
  privacy_class: string;
  provider_privacy_class: string;
  /** Every provider that serves this model, with that route's own privacy class. */
  provider_routes?: ProviderRoute[];
  context_window: number;
  max_output_tokens?: number | null;
  pricing: {
    input_usd_per_million_tokens: number;
    output_usd_per_million_tokens: number;
    unit_usd?: number | null;
  };
  capabilities: {
    streaming: boolean;
    tools: boolean;
    vision?: boolean;
    web?: boolean;
    reasoning?: {
      supported: boolean;
      effort_configurable: boolean;
      supported_efforts: string[];
      can_disable: boolean;
      default_effort: string | null;
      always_on: boolean;
    };
  };
  auto_provider?: string;
}

export type ChatRole = "system" | "user" | "assistant";

export type ChatContentPart =
  | { type: "text"; text: string }
  | { type: "image_url"; image_url: { url: string } };

export interface ChatMessage {
  role: ChatRole;
  content: string | ChatContentPart[];
}

/**
 * Provider routing. Omit for Auto (AnonRouter's privacy-first policy). A bare
 * string pins a single provider; an object is a full provider policy forwarded
 * verbatim. AnonRouter binds the normalized policy into the single-use ticket,
 * so the client sends it identically at issuance and redemption.
 */
export type ProviderRequest = string | Record<string, unknown>;

export interface ChatRequest {
  model: string;
  provider?: ProviderRequest;
  /**
   * Output ceiling. Forwarded as max_completion_tokens on the ticket and as
   * max_tokens on the completion body, so the two requests cannot disagree.
   */
  maxTokens?: number;
  /** Reasoning override ("none" or an effort the model attests). Omit for the default. */
  reasoningEffort?: string;
  messages: ChatMessage[];
  /** When true, chat() resolves to the raw Response so the caller can read the SSE stream. */
  stream?: boolean;
  /** Optional AbortSignal, applied to both the ticket and completion requests. */
  signal?: AbortSignal;
}

/**
 * An embedding request over the same two-origin ticketed flow as chat.
 *
 * Embeddings are the cheapest real call AnonRouter serves, which makes them the
 * natural canary for "this route actually runs" on a route family whose only
 * published model is an embedding model — AnonRouter's single Tinfoil TEE
 * embedding row is exactly that, and a chat request cannot reach it at all.
 */
export interface EmbeddingRequest {
  model: string;
  /** Pin a provider. Omit for Auto, which selects a route per request. */
  provider?: ProviderRequest;
  input: string | string[];
  encodingFormat?: "float" | "base64";
  dimensions?: number;
  signal?: AbortSignal;
}

/**
 * Everything the control plane is told in order to mint a ticket. Routing and
 * authorization metadata only: no messages, no embedding input, no prompt.
 */
interface TicketRequest {
  model: string;
  provider?: ProviderRequest;
  /** Omitted for chat, which is the control plane's default operation. */
  operation?: "embeddings";
  maxTokens?: number;
  reasoningEffort?: string;
  signal?: AbortSignal;
}

export interface EmbeddingVector {
  object: string;
  index: number;
  embedding: number[] | string;
}

export interface EmbeddingResponse {
  object: string;
  model: string;
  data: EmbeddingVector[];
  usage?: { prompt_tokens: number; total_tokens: number };
}

export interface ChatCompletionMessage {
  role: "assistant";
  content: string | null;
  /** Present when the model emits separate reasoning content. */
  reasoning?: string | null;
}

export interface ChatCompletionChoice {
  index: number;
  message: ChatCompletionMessage;
  finish_reason: string | null;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletion {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage?: ChatCompletionUsage;
}

/** Error raised for non-2xx responses. Keeps the HTTP status for retry policies. */
export class AnonrouterApiError extends Error {
  readonly status: number;
  readonly requestId: string | undefined;

  constructor(message: string, status: number, requestId?: string) {
    super(message);
    this.name = "AnonrouterApiError";
    this.status = status;
    this.requestId = requestId;
  }
}

export interface AnonrouterClient {
  /** List models available to this API key. GET /v1/models with the Bearer key. */
  models(): Promise<ListResponse<ModelInfo>>;
  /** Streaming chat: resolves to the raw Response so the caller can read the SSE body. */
  chat(request: ChatRequest & { stream: true }): Promise<Response>;
  /** Non-streaming chat: resolves to the parsed completion. */
  chat(request: ChatRequest & { stream?: false }): Promise<ChatCompletion>;
  /** Fallback overload for callers whose stream flag is not a literal. */
  chat(request: ChatRequest): Promise<Response | ChatCompletion>;
  /** Embeddings, over the same ticketed split: key to control, content to the relay. */
  embeddings(request: EmbeddingRequest): Promise<EmbeddingResponse>;
}

interface ApiErrorBody {
  message?: string;
  error?: { message?: string; request_id?: string };
}

/** Normalize an origin string: strip trailing slashes, nothing more. */
function trimOrigin(value: string): string {
  return value.replace(/\/+$/, "");
}

async function toApiError(response: Response): Promise<AnonrouterApiError> {
  let message = `Request failed with status ${response.status}`;
  let requestId: string | undefined;
  try {
    const body = (await response.json()) as ApiErrorBody;
    message = body.error?.message ?? body.message ?? message;
    requestId = body.error?.request_id;
  } catch {
    // Non-JSON error body: keep the status-derived message.
  }
  return new AnonrouterApiError(message, response.status, requestId);
}

/**
 * Create an AnonRouter API client bound to a base URL and API key.
 */
export function createClient(options: ClientOptions): AnonrouterClient {
  if (!options.apiKey) {
    throw new Error("createClient: apiKey is required.");
  }
  // An ABSENT origin means "use the production defaults". An origin that was
  // supplied and is empty is a misconfiguration -- `baseUrl: process.env.X ?? ""`
  // is the usual way to arrive here -- and quietly defaulting it would send
  // content to production when the caller believed they had configured
  // something else.
  for (const [name, value] of [
    ["baseUrl", options.baseUrl],
    ["controlBaseUrl", options.controlBaseUrl],
    ["inferenceBaseUrl", options.inferenceBaseUrl]
  ] as const) {
    if (value !== undefined && value.trim() === "") {
      throw new Error(`createClient: ${name} was supplied but empty. Omit it to use the default origin.`);
    }
  }
  // `baseUrl` and `inferenceBaseUrl` name the same thing. Two different values is
  // an ambiguous configuration, and the ambiguity is about where content goes,
  // so it is refused instead of resolved by precedence.
  if (
    options.baseUrl && options.inferenceBaseUrl
    && trimOrigin(options.baseUrl) !== trimOrigin(options.inferenceBaseUrl)
  ) {
    throw new Error(
      "createClient: baseUrl and inferenceBaseUrl name the same origin and must not disagree. Set one of them."
    );
  }

  const apiKey = options.apiKey;
  const doFetch: FetchLike = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new Error(
      "createClient: no fetch implementation available. Pass options.fetch or run on a fetch-capable runtime."
    );
  }

  const configuredInference = options.inferenceBaseUrl ?? options.baseUrl;
  // Preserve same-origin behaviour for custom/self-hosted deployments. Both
  // production content names use the credential-only control origin unless the
  // caller explicitly overrides it.
  const normalizedInference = configuredInference === undefined ? undefined : trimOrigin(configuredInference);
  const implicitControlOrigin = normalizedInference === undefined || PRODUCTION_INFERENCE_ORIGINS.has(normalizedInference)
    ? DEFAULT_CONTROL_ORIGIN
    : normalizedInference;
  const controlOrigin = trimOrigin(options.controlBaseUrl ?? implicitControlOrigin);
  const inferenceOrigin = trimOrigin(configuredInference ?? DEFAULT_INFERENCE_ORIGIN);
  /** URL for a content-free, API-key-authenticated request. */
  const controlUrl = (path: string): string => `${controlOrigin}/${path.replace(/^\/+/, "")}`;
  /** URL for a request that carries CONTENT and only the single-use ticket. */
  const contentUrl = (path: string): string => `${inferenceOrigin}/${path.replace(/^\/+/, "")}`;

  async function models(): Promise<ListResponse<ModelInfo>> {
    const response = await doFetch(controlUrl("/v1/models"), {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${apiKey}`
      }
    });
    if (!response.ok) {
      throw await toApiError(response);
    }
    return (await response.json()) as ListResponse<ModelInfo>;
  }

  // Control-plane request: exchanges the API key for a short-lived, single-use
  // inference ticket. This is the only request that carries the API key and it
  // carries no content, only routing and authorization metadata.
  //
  // It takes its OWN narrow shape rather than a chat or embedding request. The
  // boundary this client exists to hold is "the credential and the content never
  // travel together", and a function that accepts the whole content-bearing
  // request and remembers to leave the content out is one careless spread away
  // from breaking it. What can be sent here is what this type can express.
  async function requestTicket(request: TicketRequest): Promise<string> {
    const { operation, maxTokens, reasoningEffort } = request;
    const response = await doFetch(controlUrl("/v1/inference/tickets"), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: request.model,
        ...(request.provider !== undefined ? { provider: request.provider } : {}),
        ...(operation !== undefined ? { operation } : {}),
        ...(maxTokens !== undefined ? { max_completion_tokens: maxTokens } : {}),
        ...(reasoningEffort ? { reasoning_effort: reasoningEffort } : {})
      }),
      signal: request.signal
    });
    if (!response.ok) {
      throw await toApiError(response);
    }
    const issued = (await response.json()) as { ticket?: unknown };
    if (typeof issued.ticket !== "string" || issued.ticket.length === 0) {
      throw new Error("AnonRouter returned an invalid inference ticket.");
    }
    return issued.ticket;
  }

  async function embeddings(request: EmbeddingRequest): Promise<EmbeddingResponse> {
    // `operation: "embeddings"` is what makes the control plane price and reserve
    // this as an embedding rather than a chat turn; without it the mint refuses
    // an embedding-only model with `model_not_chat`.
    const ticket = await requestTicket({
      model: request.model,
      provider: request.provider,
      operation: "embeddings",
      signal: request.signal
    });

    const response = await doFetch(contentUrl("/v1/embeddings"), {
      method: "POST",
      // Content request: the single-use ticket and nothing else. Same rule as
      // chat -- the text being embedded is content, and content never travels
      // with the account credential.
      credentials: "omit",
      headers: {
        "content-type": "application/json",
        "x-anonrouter-ticket": ticket
      },
      body: JSON.stringify({
        model: request.model,
        input: request.input,
        ...(request.encodingFormat ? { encoding_format: request.encodingFormat } : {}),
        ...(request.dimensions !== undefined ? { dimensions: request.dimensions } : {})
      }),
      signal: request.signal
    });
    if (!response.ok) {
      throw await toApiError(response);
    }
    return (await response.json()) as EmbeddingResponse;
  }

  async function chat(request: ChatRequest): Promise<Response | ChatCompletion> {
    const ticket = await requestTicket(request);
    const stream = request.stream === true;

    const body = {
      model: request.model,
      ...(request.provider !== undefined ? { provider: request.provider } : {}),
      ...(request.maxTokens !== undefined ? { max_tokens: request.maxTokens } : {}),
      ...(request.reasoningEffort ? { reasoning_effort: request.reasoningEffort } : {}),
      stream,
      messages: request.messages
    };

    const response = await doFetch(contentUrl("/v1/chat/completions"), {
      method: "POST",
      // Content request: presents ONLY the single-use ticket. The API key and
      // any cookie are deliberately withheld, so content is not linkable to the
      // account by this request.
      credentials: "omit",
      headers: {
        "content-type": "application/json",
        "x-anonrouter-ticket": ticket
      },
      body: JSON.stringify(body),
      signal: request.signal
    });

    if (!response.ok) {
      throw await toApiError(response);
    }
    if (stream) {
      return response;
    }
    return (await response.json()) as ChatCompletion;
  }

  return {
    models,
    chat: chat as AnonrouterClient["chat"],
    embeddings
  };
}
