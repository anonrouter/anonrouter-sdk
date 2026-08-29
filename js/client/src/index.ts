/**
 * @anonrouter/client
 *
 * A thin, dependency-free client for AnonRouter's public API. It targets the
 * plaintext, TEE, and private routes and speaks the OpenAI-style chat surface
 * over AnonRouter's two-request ticketed flow.
 *
 * This is NOT the confidential client. On these routes AnonRouter's gateway can
 * still see request content (TEE protects content from the host, not from the
 * gateway). For content AnonRouter must never see, use @anonrouter/confidential,
 * which performs end-to-end encryption bound to independent attestation.
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
   */
  baseUrl: string;
  /**
   * Workspace API key. Sent as a Bearer credential on control-plane requests
   * only (model listing, ticket issuance). It is never attached to the request
   * that carries content.
   */
  apiKey: string;
  /** Optional fetch override (for tests, proxies, or non-global runtimes). */
  fetch?: FetchLike;
}

/** The {object, data} list envelope AnonRouter returns for collections. */
export interface ListResponse<T> {
  object: "list";
  data: T[];
}

/**
 * A model as returned by GET /v1/models. Fields mirror the public gateway shape.
 * Additional fields may be present on newer gateways and are preserved verbatim.
 */
export interface ModelInfo {
  id: string;
  object: "model";
  created: number;
  owned_by: string;
  display_name?: string;
  provider: string;
  model_type?: "text" | "image" | "tts";
  privacy_class: string;
  provider_privacy_class: string;
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
}

interface ApiErrorBody {
  message?: string;
  error?: { message?: string; request_id?: string };
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
  if (!options.baseUrl) {
    throw new Error("createClient: baseUrl is required.");
  }
  if (!options.apiKey) {
    throw new Error("createClient: apiKey is required.");
  }

  const apiKey = options.apiKey;
  const doFetch: FetchLike = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new Error(
      "createClient: no fetch implementation available. Pass options.fetch or run on a fetch-capable runtime."
    );
  }

  const origin = options.baseUrl.replace(/\/+$/, "");
  const url = (path: string): string => `${origin}/${path.replace(/^\/+/, "")}`;

  async function models(): Promise<ListResponse<ModelInfo>> {
    const response = await doFetch(url("/v1/models"), {
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
  async function requestTicket(request: ChatRequest): Promise<string> {
    const response = await doFetch(url("/v1/inference/tickets"), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: request.model,
        ...(request.provider !== undefined ? { provider: request.provider } : {}),
        ...(request.maxTokens !== undefined ? { max_completion_tokens: request.maxTokens } : {}),
        ...(request.reasoningEffort ? { reasoning_effort: request.reasoningEffort } : {})
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

    const response = await doFetch(url("/v1/chat/completions"), {
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
    chat: chat as AnonrouterClient["chat"]
  };
}
