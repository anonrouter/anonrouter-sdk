# `anonrouter-dcap-verifier`

The offline Intel TDX quote verifier the SDK drives to reach `hardware_verified`
on hop 1. It reads one JSON request on stdin, writes one JSON verdict on stdout,
and **performs no network access**: collateral is supplied by the caller, so the
engine's answer is a pure function of its inputs.

## Why it is here and not inside the packages

`@anonrouter/confidential` and `anonrouter-confidential` bundle no engine. A
package that shipped a prebuilt binary would be asking you to accept, on faith,
that the binary is the reviewed one — and the single component whose failure mode
is printing `hardware_verified` for a forged quote is the worst place to spend
that faith.

What is here instead is the source, a pinned toolchain, and a build that a third
party can repeat. The release then carries a `linux/amd64` build of exactly this
source so you have something to compare *against*, not something to trust.

## Licensing

**This directory is AGPL-3.0-only** ([`LICENSE`](dcap-verifier/LICENSE)). The rest
of the repository is Apache-2.0. The boundary is the directory: nothing under
`js/`, `python/` or `shared/` links against or includes this crate, and neither
published package contains it. If you distribute the compiled verifier, the AGPL
obligations that come with it are yours to meet — the GitHub release ships the
corresponding source alongside the binary for exactly that reason.

## Build it yourself

```bash
scripts/build-dcap-verifier.sh --reproduce
```

That builds twice from clean inside a registry image pinned **by digest**, and
fails unless the two outputs are byte-identical. It prints the SHA-256 you can
compare against the release asset. Docker is required; nothing else is.

The determinism controls, and what each one would otherwise let vary, are
documented at the top of that script. The short version: the builder image, the
Rust toolchain (`rust-toolchain.toml`), the dependency graph (`Cargo.lock`, built
with `--locked`) and the `dcap-qvl` version (`=0.6.1`, an exact pin because
CVE-2026-22696 is what a caret range could have moved you onto) are all fixed,
and the host's paths, clock, locale and timezone are all normalised away.

A digest that does not match ours is a finding worth reporting, not a rounding
error. A digest that does match tells you the release asset was built from the
source in front of you.

## Point the SDK at it

```bash
export ANONROUTER_DCAP_VERIFIER_BIN=/path/to/anonrouter-dcap-verifier
anonrouter-verify doctor --origin https://api.anonrouter.ai
```

`doctor` reports which engine would actually run and its SHA-256. The adapter can
also pin it: set `expectedBinarySha256` / `expected_binary_sha256` and a swapped
binary becomes a refusal rather than a different answer.

## Other targets

Only `linux/amd64` is published, because only `linux/amd64` has a reproducible
artifact today. Building for another host is a `cargo build` away and is
supported; what is not supported is *claiming* a reproducible artifact for a
target where nobody has produced one.
