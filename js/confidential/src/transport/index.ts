// Resolve a provider transport. Unlike the browser app (which dynamically imports
// to keep Noble out of the default chat bundle), the SDK is a dedicated dependency,
// so the transports are resolved synchronously here.

import { ConfidentialError } from "../errors.js";
import { nearTransport } from "./near.js";
import { veniceTransport } from "./venice.js";
import { chutesTransport } from "./chutes.js";
import type { E2eeProviderId, E2eeTransport } from "./types.js";

const TRANSPORTS: Record<E2eeProviderId, E2eeTransport> = {
  "near-ai": nearTransport,
  venice: veniceTransport,
  chutes: chutesTransport
};

/** True when the provider has a client-opaque E2EE transport. */
export function isE2eeProvider(provider: string): provider is E2eeProviderId {
  return provider === "near-ai" || provider === "venice" || provider === "chutes";
}

export function transportFor(provider: string): E2eeTransport {
  if (!isE2eeProvider(provider)) {
    throw new ConfidentialError("provider_unsupported", "That provider does not support client encryption.");
  }
  return TRANSPORTS[provider];
}
