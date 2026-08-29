// The map of canonical shared pin files to their generated per-package copies.
// Imported by BOTH sync-shared.mjs and check-parity.mjs, so the writer and the
// drift gate can never disagree about which files are covered. Data only: importing
// this module must never have a side effect, or the read-only gate would start
// writing the very files it is meant to check.
//
//   measurements.json      pins for the UPSTREAM provider enclaves (hop 2)
//   gateway-policies.json  pins for AnonRouter's own confidential plane (hop 1)

export const SYNCED_FILES = {
  "shared/measurements.json": [
    "js/confidential/src/measurements.json",
    "python/src/anonrouter_confidential/measurements.json"
  ],
  "shared/gateway-policies.json": [
    "js/confidential/src/gateway/gateway-policies.json",
    "python/src/anonrouter_confidential/gateway_policies.json"
  ]
};
