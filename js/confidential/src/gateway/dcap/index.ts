// @anonrouter/confidential/dcap: the official hardware-verification path. NODE ONLY.
//
// Import this to reach `hardware_verified`. It drives AnonRouter's reviewed
// offline DCAP engine over a process boundary and acquires the Intel-signed
// collateral that engine needs.
//
//   import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";
//
//   const verdict = await client.verifyRoute({
//     model, provider,
//     gateway: { chainVerifier: createAnonRouterDcapVerifier() }
//   });
//
// Importing this module in a browser build will fail to resolve
// node:child_process, by design: there is no browser DCAP path in this package,
// and a browser that could not run the engine must fail closed rather than
// silently verify less.

export {
  // The adapter
  createAnonRouterDcapVerifier,
  preparedDcapVerifier,
  type AnonRouterDcapVerifierOptions,
  // Locating and identifying the engine
  resolveDcapVerifierBinary,
  describeDcapInstallation,
  dcapPlatformTarget,
  fileSha256,
  DCAP_ENGINE_PROGRAM,
  DCAP_ENGINE_ENV,
  DCAP_ENGINE_REQUEST_VERSION,
  type ResolvedDcapBinary,
  type DcapBinaryOrigin,
  type DcapInstallationReport,
  // The wire contract, exported so it can be pinned by known-answer vectors
  buildDcapEngineRequest,
  parseDcapEngineVerdict,
  runDcapEngine,
  engineReportDisagreement,
  type DcapEngineRequestV1,
  type DcapEngineVerdictV1,
  type DcapTdReport
} from "./engine.js";

export {
  fetchIntelCollateral,
  CollateralCache,
  CollateralError,
  extractPckChain,
  extractFmspc,
  sliceSignedDocument,
  readSignedDocumentSignature,
  readNextUpdateMs,
  normalizeQuoteHex,
  INTEL_PCS_BASE,
  INTEL_CERT_BASE,
  type DcapCollateral,
  type AcquiredCollateral,
  type FetchCollateralOptions
} from "./collateral.js";
