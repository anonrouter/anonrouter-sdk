import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { NoSuchModelError } from "@ai-sdk/provider";
import type {
  EmbeddingModelV4,
  LanguageModelV4,
  LanguageModelV4CallOptions,
  ProviderV4,
  SharedV4Headers,
  SharedV4ProviderMetadata,
} from "@ai-sdk/provider";
import { z } from "zod/v4";
import {
  resolveChatOptions,
  resolveEmbeddingOptions,
  withWebSearch,
} from "./options.js";
import type {
  AnonRouterChatSettings,
  AnonRouterEmbeddingSettings,
  AnonRouterMode,
} from "./options.js";
import { apiBaseURL, createTransport } from "./transport.js";

export type {
  AnonRouterChatSettings,
  AnonRouterEmbeddingSettings,
  AnonRouterMode,
  AnonRouterProviderPolicy,
} from "./options.js";

export interface AnonRouterProviderSettings {
  /** Server-side inference key. Defaults to ANONROUTER_API_KEY. */
  apiKey?: string;
  /** Inference API base URL. Defaults to https://api.anonrouter.ai/v1. */
  baseURL?: string;
  /** Ticket issuer base URL. Defaults to https://control.anonrouter.ai/v1. */
  controlBaseURL?: string;
  /** Private ticket flow is the default. Compatibility uses a bearer key for inference. */
  mode?: AnonRouterMode;
  /** Additional inference headers. The provider manages authentication and cookies. */
  headers?: Record<string, string>;
  /** Optional app attribution sent as X-Title. */
  appName?: string;
  /** Optional app attribution. Only its HTTP(S) origin is sent as HTTP-Referer. */
  appUrl?: string;
  /** Trusted fetch override, called with redirect protection and credentials omitted. */
  fetch?: typeof fetch;
}

export interface AnonRouterProvider extends ProviderV4 {
  (modelId: string, settings?: AnonRouterChatSettings): LanguageModelV4;
  languageModel(modelId: string, settings?: AnonRouterChatSettings): LanguageModelV4;
  chat(modelId: string, settings?: AnonRouterChatSettings): LanguageModelV4;
  chatModel(modelId: string, settings?: AnonRouterChatSettings): LanguageModelV4;
  embedding(modelId: string, settings?: AnonRouterEmbeddingSettings): EmbeddingModelV4;
  embeddingModel(modelId: string, settings?: AnonRouterEmbeddingSettings): EmbeddingModelV4;
  textEmbeddingModel(modelId: string, settings?: AnonRouterEmbeddingSettings): EmbeddingModelV4;
}

const responseFields = z.object({
  usage: z.object({ cost: z.number().nonnegative().nullish() }).nullish(),
  web_search: z.object({
    searches: z.number().int().nonnegative(),
    model_calls: z.number().int().nonnegative(),
    cost: z.number().nonnegative(),
    model_cost: z.number().nonnegative(),
    results: z.array(z.object({
      title: z.string(),
      url: z.string(),
      description: z.string(),
    })),
  }).nullish(),
});

function responseMetadata(parsedBody: unknown): SharedV4ProviderMetadata["anonrouter"] {
  const response = responseFields.safeParse(parsedBody);
  if (!response.success) return {};
  const { usage, web_search: webSearch } = response.data;
  return {
    ...(usage?.cost != null ? { cost: usage.cost } : {}),
    ...(webSearch ? { webSearch } : {}),
  };
}

function routeMetadata(
  headers: SharedV4Headers | undefined,
  metadata?: SharedV4ProviderMetadata,
): SharedV4ProviderMetadata {
  const route = { ...metadata?.anonrouter };
  const fields = {
    selectedModel: "selected-model",
    provider: "provider",
    routing: "routing",
    privacyClass: "privacy-class",
  };
  for (const [field, suffix] of Object.entries(fields)) {
    const value = headers?.[`x-anonrouter-${suffix}`];
    if (value) route[field] = value;
  }

  const attempts = headers?.["x-anonrouter-provider-attempts"];
  if (attempts && /^\d+$/.test(attempts) && Number.isSafeInteger(Number(attempts))) {
    route.providerAttempts = Number(attempts);
  }
  const fallback = headers?.["x-anonrouter-provider-fallback"];
  if (fallback === "true" || fallback === "false") route.providerFallback = fallback === "true";
  return { ...metadata, anonrouter: route };
}

function attributionOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("AnonRouter appUrl must use HTTP or HTTPS.");
  }
  return url.origin;
}

export function createAnonRouter(options: AnonRouterProviderSettings = {}): AnonRouterProvider {
  const mode = options.mode ?? "private";
  if (mode !== "private" && mode !== "compatibility") throw new TypeError("Invalid AnonRouter mode.");

  const baseURL = apiBaseURL(options.baseURL ?? "https://api.anonrouter.ai/v1");
  const controlBaseURL = apiBaseURL(options.controlBaseURL ?? "https://control.anonrouter.ai/v1");
  if (mode === "private" && new URL(baseURL).origin === new URL(controlBaseURL).origin) {
    throw new TypeError("Private AnonRouter requests require separate API and control origins.");
  }

  const transport = { mode, baseURL, controlBaseURL, apiKey: options.apiKey, fetch: options.fetch };
  const headers = {
    ...(options.appName ? { "x-title": options.appName } : {}),
    ...(options.appUrl ? { "http-referer": attributionOrigin(options.appUrl) } : {}),
    ...options.headers,
  };
  const compatible = createOpenAICompatible({
    name: "anonrouter",
    baseURL,
    headers,
    fetch: createTransport(transport),
    includeUsage: true,
    supportsStructuredOutputs: true,
    transformRequestBody: withWebSearch,
    metadataExtractor: {
      async extractMetadata({ parsedBody }) {
        return { anonrouter: responseMetadata(parsedBody) };
      },
      createStreamExtractor() {
        const metadata: SharedV4ProviderMetadata["anonrouter"] = {};
        return {
          processChunk(chunk) {
            Object.assign(metadata, responseMetadata(chunk));
          },
          buildMetadata: () => ({ anonrouter: metadata }),
        };
      },
    },
  });

  const chat = (modelId: string, settings?: AnonRouterChatSettings): LanguageModelV4 => {
    const model = compatible.chatModel(modelId);
    function prepare(call: LanguageModelV4CallOptions): LanguageModelV4CallOptions {
      const native = resolveChatOptions(modelId, mode, settings, call.providerOptions?.anonrouter);
      return {
        ...call,
        reasoning: native.reasoning || native.reasoning_effort !== undefined ? undefined : call.reasoning,
        providerOptions: { anonrouter: native },
      };
    }

    return {
      specificationVersion: model.specificationVersion,
      provider: model.provider,
      modelId,
      get supportedUrls() { return model.supportedUrls; },
      async doGenerate(call) {
        const result = await model.doGenerate(prepare(call));
        return {
          ...result,
          providerMetadata: routeMetadata(result.response?.headers, result.providerMetadata),
        };
      },
      async doStream(call) {
        const result = await model.doStream(prepare(call));
        const responseHeaders = result.response?.headers;
        return {
          ...result,
          stream: result.stream.pipeThrough(new TransformStream({
            transform(part, controller) {
              controller.enqueue(part.type === "finish"
                ? { ...part, providerMetadata: routeMetadata(responseHeaders, part.providerMetadata) }
                : part);
            },
          })),
        };
      },
    };
  };

  const embedding = (modelId: string, settings?: AnonRouterEmbeddingSettings): EmbeddingModelV4 => {
    const model = compatible.embeddingModel(modelId);
    return {
      specificationVersion: model.specificationVersion,
      provider: model.provider,
      modelId,
      maxEmbeddingsPerCall: model.maxEmbeddingsPerCall,
      supportsParallelCalls: model.supportsParallelCalls,
      async doEmbed(call) {
        const native = resolveEmbeddingOptions(modelId, mode, settings, call.providerOptions?.anonrouter);
        // The embedding payload is strict. Apply provider selection at issuance
        // without adding a provider field to the content request.
        const selected = native.provider === undefined
          ? model
          : createOpenAICompatible({
              name: "anonrouter",
              baseURL,
              headers,
              fetch: createTransport(transport, native.provider),
            }).embeddingModel(modelId);
        const result = await selected.doEmbed(call);
        return {
          ...result,
          providerMetadata: routeMetadata(result.response?.headers, result.providerMetadata),
        };
      },
    };
  };

  return Object.assign(chat, {
    specificationVersion: "v4" as const,
    chat,
    chatModel: chat,
    languageModel: chat,
    embedding,
    embeddingModel: embedding,
    textEmbeddingModel: embedding,
    imageModel(modelId: string): never {
      throw new NoSuchModelError({ modelId, modelType: "imageModel" });
    },
  });
}

export const anonrouter = createAnonRouter();
