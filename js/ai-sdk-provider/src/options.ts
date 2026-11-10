import { z } from "zod/v4";

const privacy = z.enum(["anonymous", "private", "tee", "e2ee"]);
const providerId = z.string().min(1).max(64);
const providerList = z.array(providerId).max(16);
const price = z.number().min(0).max(1_000_000);
const provider = z.union([
  providerId,
  z.strictObject({
    order: providerList.min(1).optional(),
    only: providerList.min(1).optional(),
    ignore: providerList.optional(),
    allow_fallbacks: z.boolean().optional(),
    sort: z.enum(["privacy", "price", "latency", "throughput"]).optional(),
    minimum_privacy: privacy.optional(),
    max_price: z.strictObject({ input: price.optional(), output: price.optional() }).optional(),
    require_parameters: z.boolean().optional(),
    max_attempts: z.number().int().min(1).max(3).optional(),
  }),
]);

const modelId = z.string().min(1).max(256);
const fallbackModelId = modelId.refine((value) => value.trim().length > 0 && !value.includes("*"));
const pattern = z.array(modelId).max(32);
const effort = z.enum(["none", "minimal", "low", "medium", "high", "xhigh", "max"]);
const webSearch = z.strictObject({
  maxUses: z.number().int().min(1).max(3).optional(),
  maxResults: z.number().int().min(1).max(8).optional(),
  maxTotalResults: z.number().int().min(1).max(15).optional(),
});

const chatOptions = z.strictObject({
  provider: provider.optional(),
  routing: z.strictObject({
    allow: pattern.min(1).optional(),
    exclude: pattern.optional(),
    strategy: z.enum(["cost", "balanced", "quality"]).optional(),
    max_cost_usd: z.number().positive().max(1000).optional(),
    privacy_classes: z.array(privacy.or(z.literal("unknown"))).min(1).max(5).optional(),
  }).optional(),
  models: z.array(fallbackModelId).max(4).optional(),
  reasoning_effort: effort.optional(),
  reasoning: z.strictObject({
    enabled: z.boolean().optional(),
    effort: effort.optional(),
  }).optional(),
  venice_parameters: z.strictObject({
    strip_thinking_response: z.boolean().optional(),
    disable_thinking: z.boolean().optional(),
    include_venice_system_prompt: z.literal(false).optional(),
  }).optional(),
  parallel_tool_calls: z.boolean().optional(),
  webSearch: z.union([z.boolean(), webSearch]).optional(),
});

const embeddingOptions = z.strictObject({ provider: provider.optional() });

export type AnonRouterProviderPolicy = z.infer<typeof provider>;
export type AnonRouterChatSettings = z.infer<typeof chatOptions>;
export type AnonRouterEmbeddingSettings = z.infer<typeof embeddingOptions>;
export type AnonRouterMode = "private" | "compatibility";

export function resolveChatOptions(
  model: string,
  mode: AnonRouterMode,
  settings: AnonRouterChatSettings | undefined,
  options: unknown,
): AnonRouterChatSettings {
  const result = chatOptions.safeParse({ ...settings, ...(options as object | undefined) });
  if (!result.success) throw new TypeError("Invalid providerOptions.anonrouter chat settings.");
  const value = result.data;
  if (mode === "private" && value.models?.length) {
    throw new TypeError("AnonRouter cross-model fallbacks require compatibility mode.");
  }
  if (value.routing?.privacy_classes?.every((tier) => tier === "e2ee")) {
    throw new TypeError("E2EE routes require @anonrouter/confidential.");
  }
  requirePlaintextModel(model, value.provider);
  for (const fallback of value.models ?? []) requirePlaintextModel(fallback, value.provider);
  return value;
}

export function resolveEmbeddingOptions(
  model: string,
  mode: AnonRouterMode,
  settings: AnonRouterEmbeddingSettings | undefined,
  options: unknown,
): AnonRouterEmbeddingSettings {
  const result = embeddingOptions.safeParse({ ...settings, ...(options as object | undefined) });
  if (!result.success) throw new TypeError("Invalid providerOptions.anonrouter embedding settings.");
  const value = result.data;
  if (mode === "compatibility" && value.provider !== undefined) {
    throw new TypeError("AnonRouter embedding provider selection requires private mode.");
  }
  requirePlaintextModel(model, value.provider);
  return value;
}

function requirePlaintextModel(model: string, policy: AnonRouterProviderPolicy | undefined) {
  if (
    model.toLowerCase().split(":").slice(1).includes("e2ee") ||
    (typeof policy === "object" && policy.minimum_privacy === "e2ee")
  ) {
    throw new TypeError("E2EE routes require @anonrouter/confidential.");
  }
}

export function withWebSearch(body: Record<string, unknown>): Record<string, unknown> {
  const { webSearch: option, models, ...request } = body;
  // Models are left off when no fallback was requested. The private endpoint
  // rejects the models field even though the compatibility broker accepts it.
  if (Array.isArray(models) && models.length > 0) request.models = models;
  if (!option) return request;

  const { maxUses, maxResults, maxTotalResults } =
    typeof option === "object" ? (option as z.infer<typeof webSearch>) : {};
  request.tools = [
    ...(Array.isArray(request.tools) ? request.tools : []),
    {
      type: "anonrouter:web_search",
      parameters: { max_uses: maxUses, max_results: maxResults, max_total_results: maxTotalResults },
    },
  ];
  return request;
}
