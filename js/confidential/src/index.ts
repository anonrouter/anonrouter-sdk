// @anonrouter/confidential: independently verify AnonRouter TEE/E2EE routes and run
// confidential inference from your own Node or browser app. "Don't trust us, verify."
//
// TEE means the workload runs in a verified enclave; it does NOT by itself hide
// your content from AnonRouter. An E2EE route does: the request is encrypted to
// the provider's attested key, so AnonRouter's own build is out of your trust
// set. This package makes that distinction explicit and never emits a
// `hardware-verified` claim: the vendor-root chain is deliberately not wired, so
// the honest ceiling is `provider-attested` (near/venice/chutes) or
// `sdk-verified` (tinfoil, via its official SDK).
//
// WHICH CLASS A ROUTE IS is a per-route catalog fact, read from the route the
// gateway actually served or pinned by the caller — never inferred from the
// provider name. The same provider publishes rows in more than one class, and
// the same model id can be `tee` at one provider and `e2ee` at another.

// ---- Client -----------------------------------------------------------------
export {
  createClient,
  type AnonRouterClient,
  type CreateClientOptions,
  type VerifyAttestationInput,
  type VerifyAttestationResult,
  type VerifyGatewayInput,
  type VerifyGatewayResult,
  type VerifyGatewayOption,
  type GatewayPolicyProvenance,
  type VerifyRouteInput,
  type VerifyInput,
  type VerificationReport,
  type GatewayHopReport,
  type ProviderHopReport,
  type ChatInput,
  type ChatResult
} from "./client.js";

// ---- Ticketed media (image / speech) -----------------------------------------
// `client.images.generate(...)` and `client.audio.speech.create(...)` run the
// two-origin ticket exchange automatically. The API key mints a content-free
// single-use ticket at the control origin; the prompt or text goes only to the
// confidential inference origin, authenticated by that ticket alone. An official
// OpenAI client cannot perform this exchange: it has one base URL and one
// credential, so it would send the key and the content to the same host.
export {
  redactHeaders,
  utf16Length,
  canonicalImageSize,
  MediaError,
  DEFAULT_CONTROL_ORIGIN,
  DEFAULT_INFERENCE_ORIGIN,
  IMAGE_DEFAULT_SIZE,
  IMAGE_MIN_DIMENSION,
  IMAGE_MAX_DIMENSION,
  IMAGE_MAX_PROMPT_CHARS,
  IMAGE_RESPONSE_FORMAT,
  SPEECH_MAX_INPUT_CHARS,
  SPEECH_MAX_VOICE_CHARS,
  SPEECH_RESPONSE_FORMAT,
  type ImagesApi,
  type AudioApi,
  type SpeechApi,
  type ImageGenerateInput,
  type ImageGenerateResult,
  type GeneratedImage,
  type SpeechCreateInput,
  type SpeechCreateResult,
  type MediaResponseMetadata,
  type MediaRateLimit,
  type MediaErrorDiagnostics
} from "./media.js";

// ---- Hop 1: AnonRouter's own confidential routing plane ----------------------
// Verifying the provider's enclave says nothing about who routed the request to
// it. These verify the other half: that the AnonRouter data plane you connected
// to is the exact reviewed build, running in an Intel TDX confidential VM, bound
// to your nonce and your origin.
export {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type GatewayVerificationExpectations,
  type GatewayVerificationResult,
  type TdxChainVerifier,
  type TdxChainVerifierFactory,
  type TdxChainVerifierContext,
  type TdxChainOutcome
} from "./gateway/verify.js";
export {
  canonicalGatewayBindingJson,
  canonicalGatewayOrigin,
  gatewayBindingDigest,
  gatewayBindingHash,
  normalizeGatewayBinding,
  assertGatewayNonce,
  GatewayBindingError,
  GATEWAY_BINDING_VERSION,
  GATEWAY_BINDING_DIGEST_ALGORITHM,
  GATEWAY_BINDING_DIGEST_HEX_LENGTH,
  GATEWAY_NONCE_BYTES,
  GATEWAY_NONCE_HEX_LENGTH,
  type GatewayAttestationBinding,
  type GatewayKeyAlgorithm,
  type GatewayTransportBinding
} from "./gateway/binding.js";
export {
  loadGatewayPolicy,
  gatewayPolicyRegistry,
  pinnedGatewayPolicyFor,
  GatewayPolicyError,
  type GatewayMeasurementPolicy,
  type GatewayPlatformMeasurements,
  type GatewayPolicyEntry,
  type GatewayPolicyStatus,
  type ResolveGatewayPolicyOptions
} from "./gateway/policy.js";
export {
  parseEventLog,
  replayRtmrs,
  replayRegister,
  computeRtmr3EventDigestV1,
  rtmr3EventDigest,
  rtmr3EventDigestIsSelfConsistent,
  inconsistentRtmr3Events,
  singleEventPayload,
  EventLogError,
  RTMR_INITIAL_VALUE,
  type DstackEventLogEntry
} from "./gateway/eventLog.js";
export {
  readAttestedAppCompose,
  extractComposeImages,
  AppComposeError,
  type AttestedAppCompose,
  type AttestedImageReference
} from "./gateway/appCompose.js";

// ---- The stable verdict contract --------------------------------------------
// Prefer these over the internal VerificationLevel: the states say WHAT was
// established rather than who asserted it, and they are ordered so a threshold
// keeps meaning the same thing as the SDK evolves.
export {
  atLeast,
  isTrusted,
  describeState,
  stateForLevel,
  TRUSTED_STATES,
  type RouteVerificationState
} from "./verify/state.js";
export {
  assembleRouteVerdict,
  gatewayHopVerdict,
  providerHopVerdict,
  hopNotRequested,
  hopUnavailable,
  type RouteVerdict,
  type RouteHopVerdict,
  type RouteBindingMismatch,
  type RequestedRoute,
  type PrivacyModalitySource,
  type AssembleRouteVerdictInput
} from "./verify/route.js";

// ---- Pure verification ------------------------------------------------------
export {
  verifyRawEvidence,
  verifierFor,
  buildExpectations,
  type VerifyExpectations,
  type VerifiableProvider
} from "./verify/index.js";
export {
  toNormalizedVerdict,
  type NormalizedVerdict,
  type NormalizedAttestationResult,
  type AttestationCheck,
  type AttestationExpectations,
  type VerificationLevel,
  type HardwareType,
  type PrivacyModality,
  type TeeVerifier
} from "./verify/types.js";
export { NearTeeVerifier, type NearVerifierOptions } from "./verify/near.js";
export { VeniceTeeVerifier, type VeniceVerifierOptions } from "./verify/venice.js";
export { ChutesTeeVerifier, type ChutesVerifierOptions } from "./verify/chutes.js";
export {
  TinfoilTeeVerifier,
  TINFOIL_ENDPOINT_IDENTITY,
  type TinfoilVerifierOptions,
  type TinfoilVerificationDocument,
  type TinfoilTransportBinding
} from "./verify/tinfoil.js";

// ---- TDX quote parsing ------------------------------------------------------
export { parseTdxQuote, matchMeasurementAllowlist, type ParsedTdxQuote } from "./verify/tdx.js";

// ---- Verification crypto primitives -----------------------------------------
export {
  sha256Hex,
  sha256Bytes,
  hexEqual,
  fromHex,
  secp256k1AddressFromPublicKey,
  verifyEd25519,
  enableNodeCrypto,
  setNodeCryptoProvider
} from "./verify/crypto.js";

// ---- Measurement and provider-authority policy ------------------------------
export {
  pinnedMeasurementPolicyFor,
  pinnedEndpointIdentityFor,
  measurementPolicyDocument,
  TDX_TEE_TYPE,
  type MeasurementPolicy,
  type TdxMeasurementEntry,
  type TinfoilProviderAuthority
} from "./measurements.js";

// ---- Which routes the service currently offers -------------------------------
// A CONVENIENCE, not a security control: it refuses a withheld route early so a
// caller gets a clear answer instead of a confusing mint failure. Nothing here
// ever decides that something verified.
export {
  isRouteWithheldByService,
  withheldRouteClassification,
  withheldRouteMessage,
  OFFERED_CONFIDENTIAL_ROUTES,
  WITHHELD_CONFIDENTIAL_ROUTES,
  CONFIDENTIAL_ROUTE_POLICY_VERSION,
  type OfferedRouteKey
} from "./routePolicy.js";

// ---- Tinfoil direct verification (optional dependency, Node only) ------------
// Importing this module is browser-safe; CALLING `verifyTinfoilEnclave()` is not,
// because pinning the enclave's serving key means reading a peer certificate,
// which no browser exposes. Off Node it fails closed rather than skipping the pin.
export {
  verifyTinfoilEnclave,
  type TinfoilVerifyOptions,
  type TinfoilVerifyDependencies,
  type TinfoilSdkVerifier
} from "./tinfoil.js";
export {
  observeTinfoilTlsSpki,
  TinfoilTlsPinError,
  TinfoilTlsUnavailableError,
  type TinfoilTlsProbeOptions
} from "./tinfoil-tls.js";

// ---- E2EE transports + low-level provider crypto ----------------------------
export { transportFor, isE2eeProvider } from "./transport/index.js";
export {
  joinUrl,
  type E2eeTransport,
  type E2eeSession,
  type E2eeProviderId,
  type E2eeProtocol,
  type E2eeRole,
  type E2eeChatMessage,
  type E2eeChatRequest,
  type E2eeCompletion,
  type CreateSessionInput,
  type CompleteOptions,
  type HttpContext,
  type FetchLike
} from "./transport/types.js";
export { validateE2eeMessages, validateE2eeRequest, type RawTurnMessage } from "./transport/validation.js";

import { encryptField as nearEncryptField, decryptField as nearDecryptField } from "./transport/near.js";
import { veniceEncrypt, veniceDecrypt } from "./transport/venice.js";
import { chutesDecryptResponseJson, decryptChutesResponse } from "./transport/chutes.js";

export { nearEncryptField, nearDecryptField, veniceEncrypt, veniceDecrypt, chutesDecryptResponseJson, decryptChutesResponse };

/** The low-level provider crypto grouped by provider (exported for advanced users
 *  and exercised by the shared known-answer-test vectors). */
export const providerCrypto = {
  "near-ai": { encryptField: nearEncryptField, decryptField: nearDecryptField },
  venice: { encrypt: veniceEncrypt, decrypt: veniceDecrypt },
  chutes: { decryptResponse: decryptChutesResponse, decryptResponseJson: chutesDecryptResponseJson }
} as const;

// ---- Errors + byte helpers --------------------------------------------------
export {
  ConfidentialError,
  confidentialErrorCode,
  confidentialUserMessage,
  type ConfidentialErrorCode
} from "./errors.js";
export {
  bytesToHex,
  hexToBytes,
  base64ToBytes,
  bytesToBase64,
  randomBytes,
  utf8Encode,
  utf8Decode
} from "./bytes.js";
