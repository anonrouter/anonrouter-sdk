// Intel-signed DCAP collateral: the inputs a quote's signature is checked against.
//
// A TDX quote does not carry everything needed to judge it. The signature chains
// to Intel through a PCK certificate the quote does embed, but deciding whether
// that platform's TCB is current, whether the Quoting Enclave is one Intel
// blesses, and whether anything has been revoked needs four documents Intel
// signs and serves: TCB info for the platform's FMSPC, the QE identity, the PCK
// CRL, and the root CA CRL.
//
// WHY THE SDK FETCHES THEM RATHER THAN THE ENGINE
//
// The reviewed engine performs NO network access at all (its `report` feature,
// which is what pulls in an HTTP client, is compiled out). That is the right
// shape: a verifier that fetches its own trust inputs is only as trustworthy as
// whatever it happened to reach. Collateral is therefore acquired out here, by
// the caller's process, and handed in.
//
// NOTHING IN THIS MODULE IS A SECURITY CHECK. Everything it returns is untrusted
// input. The signatures, the issuer chains, the FMSPC relationship, and the
// freshness are all re-verified inside the engine under ITS pinned Intel root.
// That separation is deliberate: if this module were the thing that decided,
// then whoever served the collateral would be trusted, which is the arrangement
// the whole design removes. A bug here costs a failed verification, never a
// false pass.
//
// PRIVACY NOTE, stated because it is a real cost: fetching from Intel tells
// Intel which platform's FMSPC you are verifying and when. Supply `collateral`
// yourself (from a mirror, a cache, or alongside the evidence) to avoid it. The
// engine revalidates either way, so a mirror is not a party you have to trust.

import { base64ToBytes, bytesToHex, hexToBytes, isCanonicalBase64, isHex } from "../../bytes.js";
import type { FetchLike } from "../../transport/types.js";

/** Intel's Provisioning Certification Service. The only API host fetched from. */
export const INTEL_PCS_BASE = "https://api.trustedservices.intel.com";

/**
 * Intel's certificate host, which serves the root CA CRL.
 *
 * Note the trap in the file name: `IntelSGXRootCA.der` on this host is the root
 * CA's **CRL**, not its certificate. The engine pins the certificate at build
 * time; only the CRL is fetched here.
 */
export const INTEL_CERT_BASE = "https://certificates.trustedservices.intel.com";

/**
 * The collateral wire shape the AnonRouter DCAP engine accepts. Byte fields are
 * hex; the signed JSON documents are the exact bytes Intel signed.
 */
export interface DcapCollateral {
  pck_crl_issuer_chain: string;
  root_ca_crl: string;
  pck_crl: string;
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: string;
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: string;
  pck_certificate_chain?: string;
}

export interface AcquiredCollateral {
  collateral: DcapCollateral;
  /** FMSPC this collateral was fetched for, lowercase hex. */
  fmspc: string;
  /** `nextUpdate` from the signed TCB info, epoch ms. This is the cache expiry. */
  nextUpdateMs: number;
  fetchedAtMs: number;
}

export class CollateralError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CollateralError";
  }
}

/** A real TDX v4 quote is a few KB. */
const MAX_QUOTE_BYTES = 64 * 1024;
/** Bound every response so a hostile or broken endpoint cannot exhaust memory. */
const MAX_RESPONSE_CHARS = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;

/** Decode a quote given as hex or base64 into lowercase hex. Null if neither. */
export function normalizeQuoteHex(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const clean = raw.trim();
  if (clean.length === 0 || clean.length > MAX_QUOTE_BYTES * 2) return null;
  if (isHex(clean)) return clean.toLowerCase();
  if (!isCanonicalBase64(clean)) return null;
  try {
    const bytes = base64ToBytes(clean);
    return bytes.length > 0 ? bytesToHex(bytes) : null;
  } catch {
    return null;
  }
}

/** Latin-1 view of bytes, so PEM armour can be located without a UTF-8 decode. */
function latin1(bytes: Uint8Array): string {
  let out = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return out;
}

const PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
const PEM_END = "-----END CERTIFICATE-----";

/**
 * Pull the PCK certificate chain out of a quote.
 *
 * For Intel cert data type 5 the chain is embedded in the quote as PEM, so the
 * only thing that has to be fetched is the collateral that is not quote-specific.
 * Scanning for the PEM armour rather than walking the signature structure is
 * deliberate: the result is handed to the engine as untrusted input and re-parsed
 * there, so a wrong guess costs a failed verification, never a false pass.
 */
export function extractPckChain(quoteHex: string): string | null {
  const normalized = normalizeQuoteHex(quoteHex);
  if (normalized === null) return null;
  const text = latin1(hexToBytes(normalized));
  const start = text.indexOf(PEM_BEGIN);
  if (start === -1) return null;
  const end = text.lastIndexOf(PEM_END);
  if (end === -1 || end < start) return null;
  // dstack leaves NUL padding after the chain; strip it so the PEM parses.
  return text.slice(start, end + PEM_END.length).replace(/\0/g, "");
}

/** DER bytes of the first certificate in a PEM chain, or null. */
function firstCertificateDer(pemChain: string): Uint8Array | null {
  const start = pemChain.indexOf(PEM_BEGIN);
  const end = pemChain.indexOf(PEM_END, start === -1 ? 0 : start);
  if (start === -1 || end === -1) return null;
  const body = pemChain.slice(start + PEM_BEGIN.length, end).replace(/[^A-Za-z0-9+/=]/g, "");
  if (!isCanonicalBase64(body)) return null;
  try {
    return base64ToBytes(body);
  } catch {
    return null;
  }
}

/**
 * Read the FMSPC from the leaf PCK certificate's Intel SGX extension.
 *
 * The FMSPC selects which TCB info applies to this platform, so it must come out
 * of the quote rather than be configured. OID 1.2.840.113741.1.13.1.4, DER
 * encoded, followed by a 6-byte OCTET STRING. The same OID prefix can appear
 * inside other structures, so only an OCTET STRING of exactly 6 bytes is taken.
 */
export function extractFmspc(pemChain: string): string | null {
  const der = firstCertificateDer(pemChain);
  if (!der) return null;
  // 06 0a <OID 1.2.840.113741.1.13.1.4>
  const oid = hexToBytes("060a2a864886f84d010d0104");
  for (let from = 0; from + oid.length + 8 <= der.length; from += 1) {
    let matched = true;
    for (let i = 0; i < oid.length; i += 1) {
      if (der[from + i] !== oid[i]) { matched = false; break; }
    }
    if (!matched) continue;
    const tag = der[from + oid.length];
    const length = der[from + oid.length + 1];
    if (tag === 0x04 && length === 6) {
      return bytesToHex(der.subarray(from + oid.length + 2, from + oid.length + 8));
    }
  }
  return null;
}

/**
 * Slice a signed sub-document out of a PCS response by brace matching.
 *
 * `{"tcbInfo":{...},"signature":"..."}` is signed over the exact bytes of the
 * inner object. Parsing and re-serializing would produce different bytes and a
 * signature that no longer verifies, so the original bytes are sliced out.
 */
export function sliceSignedDocument(body: string, key: string): string {
  const marker = `"${key}":`;
  const at = body.indexOf(marker);
  if (at === -1) throw new CollateralError(`Intel PCS response has no ${key}`);
  const start = body.indexOf("{", at + marker.length);
  if (start === -1) throw new CollateralError(`Intel PCS ${key} is not an object`);
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < body.length; i += 1) {
    const ch = body[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return body.slice(start, i + 1);
    }
  }
  throw new CollateralError(`Intel PCS ${key} is not balanced`);
}

/** The detached signature Intel returns beside a signed document, lowercase hex. */
export function readSignedDocumentSignature(body: string): string {
  const match = /"signature"\s*:\s*"([0-9a-fA-F]+)"/.exec(body);
  if (!match) throw new CollateralError("Intel PCS response has no signature");
  return match[1].toLowerCase();
}

/** `nextUpdate` out of signed TCB info, epoch ms. This is what bounds the cache. */
export function readNextUpdateMs(tcbInfo: string): number {
  const match = /"nextUpdate"\s*:\s*"([^"]+)"/.exec(tcbInfo);
  if (!match) throw new CollateralError("signed TCB info has no nextUpdate");
  const at = Date.parse(match[1]);
  if (!Number.isFinite(at)) throw new CollateralError("signed TCB info has an unparsable nextUpdate");
  return at;
}

export interface FetchCollateralOptions {
  /** Override the Intel PCS API base, for a mirror you operate. */
  pcsBase?: string;
  /** Override the Intel certificate host, for a mirror you operate. */
  certBase?: string;
  fetch?: FetchLike;
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface TextResponse {
  body: string;
  headers: Headers;
}

async function getText(
  url: string,
  fetchImpl: FetchLike,
  signal: AbortSignal | undefined,
  accept?: string
): Promise<TextResponse> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      cache: "no-store",
      ...(accept ? { headers: { accept } } : {}),
      signal
    });
  } catch {
    throw new CollateralError(`could not reach ${new URL(url).host}`);
  }
  if (!response.ok) {
    throw new CollateralError(`${new URL(url).host} returned ${response.status} for ${new URL(url).pathname}`);
  }
  const body = await response.text();
  if (body.length > MAX_RESPONSE_CHARS) {
    throw new CollateralError(`response from ${new URL(url).host} exceeds the maximum size`);
  }
  return { body, headers: response.headers };
}

async function getDerHex(
  url: string,
  fetchImpl: FetchLike,
  signal: AbortSignal | undefined
): Promise<TextResponse> {
  let response: Response;
  try {
    response = await fetchImpl(url, { method: "GET", cache: "no-store", signal });
  } catch {
    throw new CollateralError(`could not reach ${new URL(url).host}`);
  }
  if (!response.ok) {
    throw new CollateralError(`${new URL(url).host} returned ${response.status} for ${new URL(url).pathname}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAX_RESPONSE_CHARS) {
    throw new CollateralError(`response from ${new URL(url).host} exceeds the maximum size`);
  }
  return { body: bytesToHex(bytes), headers: response.headers };
}

/**
 * Intel returns the issuer chain in a response header, URL-encoded, and the
 * signed document in the body. The header spellings differ between endpoints, so
 * each is looked up by name.
 */
function requireHeader(headers: Headers, name: string): string {
  const value = headers.get(name);
  if (!value) throw new CollateralError(`Intel PCS response is missing the ${name} header`);
  try {
    return decodeURIComponent(value);
  } catch {
    throw new CollateralError(`Intel PCS ${name} header is not valid percent-encoding`);
  }
}

/**
 * Fetch the collateral for one quote from Intel.
 *
 * Everything returned is untrusted; the engine checks it. Throws
 * `CollateralError` rather than returning a partial document, because a caller
 * that proceeded with half the collateral would get a refusal it could not
 * explain.
 */
export async function fetchIntelCollateral(
  quote: string,
  options: FetchCollateralOptions = {}
): Promise<AcquiredCollateral> {
  const quoteHex = normalizeQuoteHex(quote);
  if (quoteHex === null) throw new CollateralError("quote is neither hex nor base64");

  const pckChain = extractPckChain(quoteHex);
  if (!pckChain) {
    throw new CollateralError("quote carries no PCK certificate chain (Intel cert data type 5 expected)");
  }
  const fmspc = extractFmspc(pckChain);
  if (!fmspc) throw new CollateralError("could not read the FMSPC from the PCK certificate");

  const pcsBase = (options.pcsBase ?? INTEL_PCS_BASE).replace(/\/+$/, "");
  const certBase = (options.certBase ?? INTEL_CERT_BASE).replace(/\/+$/, "");
  const fetchImpl: FetchLike = options.fetch ?? (globalThis.fetch.bind(globalThis) as FetchLike);

  // One deadline across all four fetches, so a slow endpoint cannot extend the
  // caller's wait by four times the timeout.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  const signal = controller.signal;

  try {
    const [tcb, qe, pckCrl, rootCaCrl] = await Promise.all([
      getText(`${pcsBase}/tdx/certification/v4/tcb?fmspc=${fmspc}`, fetchImpl, signal, "application/json"),
      getText(`${pcsBase}/tdx/certification/v4/qe/identity`, fetchImpl, signal, "application/json"),
      // `encoding=der` returns raw binary, not hex text.
      getDerHex(`${pcsBase}/sgx/certification/v4/pckcrl?ca=platform&encoding=der`, fetchImpl, signal),
      // IntelSGXRootCA.der is the root CA's CRL, despite the name.
      getDerHex(`${certBase}/IntelSGXRootCA.der`, fetchImpl, signal)
    ]);

    const tcbInfo = sliceSignedDocument(tcb.body, "tcbInfo");
    const qeIdentity = sliceSignedDocument(qe.body, "enclaveIdentity");

    return {
      collateral: {
        pck_crl_issuer_chain: requireHeader(pckCrl.headers, "SGX-PCK-CRL-Issuer-Chain"),
        root_ca_crl: rootCaCrl.body,
        pck_crl: pckCrl.body,
        tcb_info_issuer_chain: requireHeader(tcb.headers, "TCB-Info-Issuer-Chain"),
        tcb_info: tcbInfo,
        tcb_info_signature: readSignedDocumentSignature(tcb.body),
        qe_identity_issuer_chain: requireHeader(qe.headers, "SGX-Enclave-Identity-Issuer-Chain"),
        qe_identity: qeIdentity,
        qe_identity_signature: readSignedDocumentSignature(qe.body),
        pck_certificate_chain: pckChain
      },
      fmspc,
      nextUpdateMs: readNextUpdateMs(tcbInfo),
      fetchedAtMs: Date.now()
    };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", onAbort);
  }
}

/**
 * An in-process cache keyed by FMSPC, expiring at the collateral's own signed
 * `nextUpdate`.
 *
 * The expiry comes from the signed document rather than from a policy constant,
 * so the cache cannot outlive what Intel signed for. The engine independently
 * rejects stale collateral, so a bug here degrades to a failed verification.
 */
export class CollateralCache {
  private readonly entries = new Map<string, AcquiredCollateral>();

  constructor(
    private readonly fetcher: (quote: string) => Promise<AcquiredCollateral> = (quote) =>
      fetchIntelCollateral(quote)
  ) {}

  /** Cached collateral for this quote's platform, fetching only when needed. */
  async get(quote: string, now: number = Date.now()): Promise<AcquiredCollateral> {
    const quoteHex = normalizeQuoteHex(quote);
    const pckChain = quoteHex === null ? null : extractPckChain(quoteHex);
    const fmspc = pckChain ? extractFmspc(pckChain) : null;
    if (fmspc) {
      const hit = this.entries.get(fmspc);
      if (hit && hit.nextUpdateMs > now) return hit;
    }
    const fresh = await this.fetcher(quote);
    this.entries.set(fresh.fmspc, fresh);
    return fresh;
  }

  peek(fmspc: string): AcquiredCollateral | undefined {
    return this.entries.get(fmspc);
  }

  clear(): void {
    this.entries.clear();
  }
}
