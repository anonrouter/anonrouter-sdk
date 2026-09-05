#!/usr/bin/env bash
# Build the linux/amd64 `anonrouter-dcap-verifier` release artifact reproducibly.
#
#   scripts/build-dcap-verifier.sh              build once, print the digest
#   scripts/build-dcap-verifier.sh --reproduce  build twice from clean and require
#                                               byte-identical output
#
# WHY A CONTAINER. The digest a user compares against is only meaningful if the
# environment that produced it is named. A host toolchain is not: two people on
# two machines get two digests and no way to tell whether the difference is the
# compiler or the source. The builder is therefore a registry image pinned BY
# DIGEST, not by tag, and the toolchain inside it is pinned again by the crate's
# own rust-toolchain.toml.
#
# WHAT IS NORMALISED, and why each one would otherwise vary:
#
#   --remap-path-prefix   rustc embeds the workspace and registry paths into the
#                         binary; `strip = true` does not remove the paths carried
#                         in panic metadata. Without this the digest depends on
#                         WHERE it was built.
#   SOURCE_DATE_EPOCH     derived from the source, never the clock.
#   CARGO_INCREMENTAL=0   incremental artifacts embed absolute paths and ordering.
#   LC_ALL / TZ           locale and timezone reach sorted output and timestamps.
#   --locked              build the committed Cargo.lock or fail; never resolve.
#
# The result is a static musl binary, so it runs on any linux/amd64 host without
# a matching libc. Other targets are not built here and must not be claimed:
# a target with no reproducible artifact has nothing for a user to check.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT/native/dcap-verifier"
OUT_DIR="${DCAP_OUT_DIR:-$ROOT/dist/artifacts}"
OUT_NAME="anonrouter-dcap-verifier-linux-amd64"

# The builder image, pinned by digest. Changing this changes every published
# digest, so it is a deliberate edit and never a routine bump.
BUILDER_IMAGE="rust:1.94.1-alpine3.22@sha256:797631f9efd6957d0013f200e410478c380907eee3b469c6f80d89022df28bc7"
TARGET="x86_64-unknown-linux-musl"

reproduce=false
for arg in "$@"; do
  case "$arg" in
    --reproduce) reproduce=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

# Derived from the source itself, so the same commit gives the same value on
# every machine. Falls back to a fixed epoch outside a git checkout (for example
# inside an extracted source tarball), which keeps the build deterministic there
# too rather than silently using the clock.
SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct -- native/dcap-verifier 2>/dev/null || true)"
[ -n "$SOURCE_DATE_EPOCH" ] || SOURCE_DATE_EPOCH=0

build_once() {
  local dest="$1"
  docker run --rm --platform linux/amd64 \
    -v "$CRATE_DIR:/src:ro" \
    -v "$dest:/out" \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e CARGO_INCREMENTAL=0 \
    -e LC_ALL=C \
    -e TZ=UTC \
    "$BUILDER_IMAGE" \
    sh -eu -c '
      apk add --no-cache musl-dev >/dev/null
      # Copy out of the read-only mount so the build cannot mutate the source
      # tree, and so the workspace path is a fixed one we then remap away.
      cp -R /src /build
      cd /build
      export CARGO_HOME=/cargo
      export RUSTFLAGS="--remap-path-prefix=/build=/anonrouter-dcap-verifier --remap-path-prefix=/cargo=/cargo -C target-feature=+crt-static"
      rustup target add '"$TARGET"' >/dev/null
      cargo build --locked --release --target '"$TARGET"'
      cp target/'"$TARGET"'/release/anonrouter-dcap-verifier /out/'"$OUT_NAME"'
    '
}

mkdir -p "$OUT_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/a"
echo "building $OUT_NAME with $BUILDER_IMAGE"
build_once "$work/a"
digest_a="$(shasum -a 256 "$work/a/$OUT_NAME" | awk '{print $1}')"

if $reproduce; then
  mkdir -p "$work/b"
  echo "rebuilding from clean to check reproducibility"
  build_once "$work/b"
  digest_b="$(shasum -a 256 "$work/b/$OUT_NAME" | awk '{print $1}')"
  if [ "$digest_a" != "$digest_b" ]; then
    echo "FAIL  the two builds differ: $digest_a vs $digest_b" >&2
    exit 1
  fi
  echo "ok    two independent builds are byte-identical"
fi

cp "$work/a/$OUT_NAME" "$OUT_DIR/$OUT_NAME"
chmod +x "$OUT_DIR/$OUT_NAME"

echo
echo "artifact   $OUT_DIR/$OUT_NAME"
echo "bytes      $(wc -c < "$OUT_DIR/$OUT_NAME" | tr -d ' ')"
echo "sha256     $digest_a"
echo "builder    $BUILDER_IMAGE"
echo "target     $TARGET"
echo "epoch      $SOURCE_DATE_EPOCH"
