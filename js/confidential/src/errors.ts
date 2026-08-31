// The single error type this package throws. Messages here may be surfaced to a
// UI and logged, so they MUST be content-free: never embed a private key, shared
// secret, ciphertext, plaintext prompt/response, nonce, or raw evidence body. A
// short machine-readable `code` plus a safe human string is all that is allowed.

export type ConfidentialErrorCode =
  | "provider_unsupported"
  | "unsupported_request"
  | "multi_turn_unsupported"
  | "attestation_ticket_failed"
  | "attestation_failed"
  | "attestation_untrusted"
  | "evidence_invalid"
  | "evidence_too_large"
  | "measurement_untrusted"
  | "key_binding_failed"
  | "nonce_mismatch"
  | "model_mismatch"
  | "inference_ticket_failed"
  | "encrypt_failed"
  | "transport_failed"
  | "response_invalid"
  | "response_too_large"
  | "decrypt_failed"
  | "cancelled"
  // ---- Ticketed media (image / speech) ----
  // These separate the failures that cost money from the ones that cannot, so a
  // caller can decide whether starting over is safe. Only `provider_failed` may
  // correspond to work a provider actually attempted.
  /** The control origin would not mint a media ticket. No content was sent. */
  | "media_ticket_failed"
  /** The issued ticket did not bind what was requested. No content was sent. */
  | "ticket_binding_mismatch"
  /** The relay rejected the ticket: expired, already spent, or drifted (401/409). */
  | "ticket_rejected"
  /** The relay refused the request outright (no ticket, disabled, quota, 4xx). */
  | "relay_refused"
  /** The request reached a provider and the generation failed there (5xx). */
  | "provider_failed"
  /** The request exceeded its deadline. */
  | "timeout";

/** The single error class every module throws. Fail-closed and content-free. */
export class ConfidentialError extends Error {
  readonly code: ConfidentialErrorCode;

  constructor(code: ConfidentialErrorCode, message: string) {
    super(message);
    this.name = "ConfidentialError";
    this.code = code;
  }
}

/** Narrow an unknown thrown value to a ConfidentialErrorCode, defaulting safely. */
export function confidentialErrorCode(error: unknown): ConfidentialErrorCode {
  return error instanceof ConfidentialError ? error.code : "transport_failed";
}

/** A user-facing message that never leaks internals. */
export function confidentialUserMessage(error: unknown): string {
  if (error instanceof ConfidentialError) return error.message;
  return "The confidential request could not be completed.";
}
