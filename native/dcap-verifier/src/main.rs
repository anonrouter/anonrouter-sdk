//! Offline Intel TDX DCAP quote verifier.
//!
//! Reads one JSON request on stdin, writes one JSON verdict on stdout, exits.
//! **It performs no network access.** The `report` feature of `dcap-qvl`, which
//! is what pulls in `reqwest` and fetches collateral, is disabled in
//! `Cargo.toml`; collateral is supplied by the caller. That is deliberate: a
//! verifier that fetches its own trust inputs is only as trustworthy as
//! whatever it happened to talk to, and on a user's machine it also leaks which
//! platform is being verified and when.
//!
//! WHY A SEPARATE EXECUTABLE
//!
//! One engine has to serve the Node server, the Node CLI (`anonrouter
//! verify-proxy`), and the Python SDK. Maintaining separate Node and Python
//! crypto bindings would mean two things to audit and two things to get wrong.
//! A process boundary with a bounded JSON contract is the cheapest way to have
//! exactly one implementation of the part that matters.
//!
//! WHAT THIS ADDS OVER CALLING `dcap_qvl::verify` DIRECTLY
//!
//! 1. **Our own pinned Intel root**, not the crate's. `assets/IntelSGXRootCA.der`
//!    is fetched from Intel and checked in. A crate upgrade that silently
//!    changed its embedded root would not change what we trust, and the test
//!    `pinned_root_matches_crate_root` fails loudly if the two ever diverge.
//! 2. **An explicit TCB gate.** `dcap_qvl::verify` returns Ok for `OutOfDate`
//!    and the `ConfigurationNeeded` family, with the status in a field. Treating
//!    "no error" as a pass silently accepts a degraded platform. Here the status
//!    must appear in an accepted set, and the QE and platform statuses are gated
//!    independently of the merged one.
//! 3. **A bounded, versioned wire format** in hex, so the contract does not
//!    depend on the crate's internal serde representation.
//!
//! EXIT CODES: 0 verified, 1 not verified, 2 unusable input. A verdict is
//! printed for 0 and 1. The build uses `panic = "abort"`, so a panic produces no
//! JSON and a non-zero exit; callers must treat unparseable output as failure.

use std::io::Read;

use dcap_qvl::quote::Report;
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::QuoteCollateralV3;
use serde::{Deserialize, Serialize};

/// Intel SGX Root CA, DER, fetched from
/// <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem>
/// SHA-256 44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3
/// subject == issuer == "CN=Intel SGX Root CA, O=Intel Corporation", valid to 2049-12-31.
static PINNED_INTEL_ROOT_CA_DER: &[u8] = include_bytes!("../assets/IntelSGXRootCA.der");

/// A hostile caller must not be able to make us allocate without bound.
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// Quotes are ~5 KB; this is generous and still bounded.
const MAX_QUOTE_BYTES: usize = 64 * 1024;

/// The only TCB status accepted unless the caller narrows it further.
///
/// `SWHardeningNeeded` is deliberately absent: accepting it requires a reviewed
/// advisory allowlist, which is a policy decision and not a default.
const DEFAULT_ACCEPTED_STATUSES: &[&str] = &["UpToDate"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Wire format version. Only 1 exists.
    v: u32,
    /// Raw TDX quote, hex.
    quote: String,
    collateral: CollateralInput,
    /// Verification time, seconds since the epoch. Supplied rather than read
    /// from the clock so verification is a pure function of its inputs and a
    /// test can pin it.
    now_secs: u64,
    /// Accepted TCB statuses. Omitted means `["UpToDate"]`.
    #[serde(default)]
    accepted_tcb_statuses: Option<Vec<String>>,
}

/// Intel-signed collateral, with byte fields hex-encoded so the contract does
/// not depend on `serde_bytes`' JSON representation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollateralInput {
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
    #[serde(default)]
    pck_certificate_chain: Option<String>,
}

#[derive(Serialize, Default)]
struct Response {
    v: u32,
    /// The single field a caller should branch on.
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcb_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qe_tcb_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_tcb_status: Option<String>,
    advisory_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<TdReport>,
    /// Why verification failed. Content-free: never echoes caller input.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Identifies the engine that produced this verdict, for the audit trail.
    engine: &'static str,
}

/// The measured fields, hex. Emitted so a caller can compare them against a
/// pinned policy without parsing the quote a second time.
#[derive(Serialize)]
struct TdReport {
    kind: &'static str,
    tee_tcb_svn: String,
    mr_seam: String,
    mr_signer_seam: String,
    td_attributes: String,
    xfam: String,
    mr_td: String,
    mr_config_id: String,
    mr_owner: String,
    mr_owner_config: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    report_data: String,
    /// Bit 0 of td_attributes. A debug TD's memory is host-readable, so nothing
    /// measured inside it is confidential.
    debug: bool,
}

const ENGINE: &str = concat!("anonrouter-dcap-verifier/", env!("CARGO_PKG_VERSION"), " dcap-qvl/0.6.1");

fn fail(error: &str) -> Response {
    Response {
        v: 1,
        verified: false,
        advisory_ids: Vec::new(),
        error: Some(error.to_string()),
        engine: ENGINE,
        ..Default::default()
    }
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.trim().trim_start_matches("0x"))
        .map_err(|_| format!("{field} is not valid hex"))
}

fn main() {
    let mut raw = Vec::new();
    // Bounded read: take(N+1) so an over-long input is detected rather than
    // silently truncated into something that might still parse.
    let read = std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut raw);
    if read.is_err() {
        emit(fail("could not read stdin"), 2);
    }
    if raw.len() > MAX_INPUT_BYTES {
        emit(fail("input exceeds the maximum size"), 2);
    }

    let request: Request = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => emit(fail("input is not a valid request document"), 2),
    };
    if request.v != 1 {
        emit(fail("unsupported request version"), 2);
    }

    match verify(&request) {
        Ok(response) => {
            let code = if response.verified { 0 } else { 1 };
            emit(response, code);
        }
        Err(error) => emit(fail(&error), 1),
    }
}

fn verify(request: &Request) -> Result<Response, String> {
    let quote = decode_hex("quote", &request.quote)?;
    if quote.is_empty() || quote.len() > MAX_QUOTE_BYTES {
        return Err("quote is empty or exceeds the maximum size".into());
    }

    let collateral = QuoteCollateralV3 {
        pck_crl_issuer_chain: request.collateral.pck_crl_issuer_chain.clone(),
        root_ca_crl: decode_hex("root_ca_crl", &request.collateral.root_ca_crl)?,
        pck_crl: decode_hex("pck_crl", &request.collateral.pck_crl)?,
        tcb_info_issuer_chain: request.collateral.tcb_info_issuer_chain.clone(),
        tcb_info: request.collateral.tcb_info.clone(),
        tcb_info_signature: decode_hex("tcb_info_signature", &request.collateral.tcb_info_signature)?,
        qe_identity_issuer_chain: request.collateral.qe_identity_issuer_chain.clone(),
        qe_identity: request.collateral.qe_identity.clone(),
        qe_identity_signature: decode_hex(
            "qe_identity_signature",
            &request.collateral.qe_identity_signature,
        )?,
        pck_certificate_chain: request.collateral.pck_certificate_chain.clone(),
    };

    // OUR pinned root, not the crate's. `allow_debug` and `allow_service_td`
    // both default to false and are deliberately left that way.
    let verifier = QuoteVerifier::new(PINNED_INTEL_ROOT_CA_DER.to_vec());

    // Any verification error is a refusal, not a crash, and its text is the
    // library's own message about the evidence rather than anything we echo.
    let verified = verifier
        .verify(&quote, &collateral, request.now_secs)
        .map_err(|error| format!("quote verification failed: {error:?}"))?;

    let accepted: Vec<String> = match &request.accepted_tcb_statuses {
        Some(list) if !list.is_empty() => list.clone(),
        _ => DEFAULT_ACCEPTED_STATUSES.iter().map(|s| s.to_string()).collect(),
    };

    let qe_status = format!("{:?}", verified.qe_status.status);
    let platform_status = format!("{:?}", verified.platform_status.status);

    let report = td_report(&verified.report);

    // THE GATE. `verify()` returns Ok for OutOfDate and the ConfigurationNeeded
    // family, so the status must be checked explicitly. All three are gated:
    // the merged status could in principle be more favourable than one of its
    // parts, and a degraded Quoting Enclave is as fatal as a degraded platform.
    let mut refusals = Vec::new();
    for (label, status) in [
        ("tcb", verified.status.as_str()),
        ("qe", qe_status.as_str()),
        ("platform", platform_status.as_str()),
    ] {
        if !accepted.iter().any(|value| value == status) {
            refusals.push(format!("{label} status {status} is not accepted"));
        }
    }
    // Defence in depth: the crate refuses debug TDs, and so do we, so a change
    // in its default cannot quietly make debug quotes acceptable here.
    if report.as_ref().is_some_and(|value| value.debug) {
        refusals.push("TD has the debug attribute set".into());
    }

    Ok(Response {
        v: 1,
        verified: refusals.is_empty(),
        tcb_status: Some(verified.status.clone()),
        qe_tcb_status: Some(qe_status),
        platform_tcb_status: Some(platform_status),
        advisory_ids: verified.advisory_ids.clone(),
        report,
        error: (!refusals.is_empty()).then(|| refusals.join("; ")),
        engine: ENGINE,
    })
}

fn td_report(report: &Report) -> Option<TdReport> {
    let (kind, td_attributes, mr_seam, mr_signer_seam, xfam, mr_td, mr_config_id, mr_owner,
         mr_owner_config, rtmr, report_data, tee_tcb_svn) = match report {
        Report::TD10(r) => ("td10", r.td_attributes, r.mr_seam, r.mr_signer_seam, r.xfam, r.mr_td,
            r.mr_config_id, r.mr_owner, r.mr_owner_config,
            [r.rt_mr0, r.rt_mr1, r.rt_mr2, r.rt_mr3], r.report_data, r.tee_tcb_svn),
        Report::TD15(r) => ("td15", r.base.td_attributes, r.base.mr_seam, r.base.mr_signer_seam,
            r.base.xfam, r.base.mr_td, r.base.mr_config_id, r.base.mr_owner, r.base.mr_owner_config,
            [r.base.rt_mr0, r.base.rt_mr1, r.base.rt_mr2, r.base.rt_mr3], r.base.report_data,
            r.base.tee_tcb_svn),
        // An SGX enclave quote is not a TD. Callers expecting a TDX gateway must
        // see no report rather than a coerced one.
        Report::SgxEnclave(_) => return None,
    };
    Some(TdReport {
        kind,
        tee_tcb_svn: hex::encode(tee_tcb_svn),
        mr_seam: hex::encode(mr_seam),
        mr_signer_seam: hex::encode(mr_signer_seam),
        td_attributes: hex::encode(td_attributes),
        xfam: hex::encode(xfam),
        mr_td: hex::encode(mr_td),
        mr_config_id: hex::encode(mr_config_id),
        mr_owner: hex::encode(mr_owner),
        mr_owner_config: hex::encode(mr_owner_config),
        rtmr0: hex::encode(rtmr[0]),
        rtmr1: hex::encode(rtmr[1]),
        rtmr2: hex::encode(rtmr[2]),
        rtmr3: hex::encode(rtmr[3]),
        report_data: hex::encode(report_data),
        debug: td_attributes[0] & 0x01 == 0x01,
    })
}

fn emit(response: Response, code: i32) -> ! {
    // serde_json cannot fail on this type; if it somehow did, exiting without
    // output still fails closed at the caller.
    if let Ok(text) = serde_json::to_string(&response) {
        println!("{text}");
    }
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_root_is_the_intel_sgx_root_ca() {
        // Guards the checked-in asset itself: a corrupted or swapped file
        // changes this digest.
        let digest = <sha2::Sha256 as sha2::Digest>::digest(PINNED_INTEL_ROOT_CA_DER);
        assert_eq!(
            hex::encode(digest),
            "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
        );
    }

    #[test]
    fn pinned_root_is_a_self_signed_intel_root() {
        // Structural sanity on the asset, independent of its digest: it must
        // parse as a certificate whose subject is its own issuer.
        let text = String::from_utf8_lossy(PINNED_INTEL_ROOT_CA_DER);
        assert!(!text.contains("BEGIN CERTIFICATE"), "asset must be DER, not PEM");
        assert_eq!(PINNED_INTEL_ROOT_CA_DER[0], 0x30, "asset must start with a DER SEQUENCE");
        // "Intel SGX Root CA" appears as both subject and issuer CN in a
        // self-signed root, so it occurs at least twice in the DER.
        let needle = b"Intel SGX Root CA";
        let count = PINNED_INTEL_ROOT_CA_DER
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count();
        assert!(count >= 2, "expected a self-signed Intel SGX Root CA, found {count} name(s)");
    }

    // The two checks that cannot live here:
    //
    // - That the pinned root is load-bearing. `dcap_qvl::constants` is private,
    //   so comparing against the crate's copy is not possible. The stronger
    //   test is behavioural and needs real collateral: verification of a good
    //   quote must FAIL under a substituted root. It lives in
    //   tests/unit/dcap-verifier.test.ts as "rejects the real quote under a
    //   substituted root CA".
    // - That `danger-allow-tcb-override` is off. It is a feature of the
    //   dependency, not of this crate, so `cfg!` here would always be false and
    //   prove nothing. It is asserted against `cargo tree` output by
    //   `scripts/dcap-verify-build.sh`.
}
