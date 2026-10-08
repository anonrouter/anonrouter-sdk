# Review: GCP content-node authorization and financial control

Independent, read-only security review requested by the coordinator
(task_3bae202357ed). Nothing in the backend checkout was edited; production,
cloud, signing and publication were untouched.

## Scope and evidence base

| Item | Value |
|---|---|
| Backend checkout | `anonrouter/gcp-content-qualification-20261008` |
| Reviewed commits | `275c4c73` (ownership + direct mTLS RPC), `68d9dd56` (RPC DB role), `eaed191e` (Redis one-use grants), HEAD `eaed191eac76bc521ac3806919b882edebaed815` |
| Uncommitted, coordinator-owned | `src/contentNodes/rpcClient.ts` (SHA-256 `83640e1c…956b`), `src/inference/controlClient.ts` (`d6c3c2f4…a243`, `post` made `protected`) |
| Traced | `ControlPlane.authorize/authorizeNextProviderAttempt/authorizeProviderAttempt/abort/settle/capture/markDeliveryStarted`, `billing.ts` reserve/fence/finalize/receipt/delivery/route/sweep, `requestOwnership.ts`, `presenter.ts`, `lifecycle.ts`, `rpcServer.ts`, migration 140 triggers, `grants.sql`, relay call sites (`routes/chat.ts`) |

Findings were proved by running probe tests in a **scratch copy** of the
backend (`git archive HEAD` plus the two uncommitted files, `node_modules`
reused read-only). The probe file reuses the committed ownership test's fixture
verbatim: a disposable PostgreSQL 16 with all real migrations, the actual
`grants.sql` applied, the `anonrouter_rpc` role, real loopback mTLS presenter
resolution and, where noted, a disposable Redis. All five probes pass (each
asserts the defect exists); the unmodified committed ownership suite also passes
13/13 in the same copy. Probe file SHA-256
`aa826b5b2dfcaed2de65f7bce2ea43c7df11e8e2cf998a055c21096aad74a62e`; the
probe bodies are in the appendix. No SDK unit suite was rerun; nothing here
changes SDK code.

Severity reflects the activation goal: node mode is disabled today, so every
finding is a **pre-activation** blocker or hardening item, not a live incident.
Each finding says whether it breaks an invariant the checkpoint claims as
accepted, or is unfinished integration already listed as gated.

## Prioritized findings

### H1. The RPC database role can forge node liveness (breaks an accepted invariant) — PROVED

- `grants.sql:51` grants `anonrouter_rpc` `UPDATE (heartbeat_sequence,
  last_heartbeat_at, lease_until)` on `providers.content_nodes`. Column
  privileges do not constrain values, and the migration-140 trigger
  (`140_content_node_request_ownership.sql:87-98`) checks identity and terminal
  state only.
- The bounds the checkpoint calls accepted ("sequences must increase … only
  extend the control lease by 30 seconds", "cannot … extend") live only in
  `lifecycle.ts:14-22` application code.
- Probe H1, as `anonrouter_rpc`: set `lease_until` ten years ahead and roll
  `heartbeat_sequence` from 7 to 0. Consequences:
  - `expireContentNodeLeases` no longer fences the boot (`lifecycle.ts:59-71`), so lease-loss failure detection is defeated.
  - An old sequence replays (`heartbeatContentNode(..., 1)` succeeds).
  - For a freshly admitted boot that never produced its controller-verified first heartbeat, setting `last_heartbeat_at` makes `resolveContentNodePresenter` succeed (`presenter.ts:46-47`). The first-heartbeat proof is bypassed.
- **Fix:** revoke the column `UPDATE`. Route heartbeat through a
  `SECURITY DEFINER` function owned by the controller that requires
  `sequence > OLD`, sets `lease_until = clock_timestamp() + 30s`, and refuses
  when `last_heartbeat_at IS NULL`, so the first heartbeat stays controller-only.
  Alternatively, add a `BEFORE UPDATE` trigger enforcing the same bounds for
  non-controller roles. Add a negative test to `content-node-ownership.test.ts`
  next to `enforces actual measured RPC database role restrictions`.

### H2. Node mode loses the provider-rejection signal that stops fallback (unfinished integration with a safety effect) — PROVED

- `rpcClient.ts:22-24` lists `/provider-rejection`, `/models` and
  `/attestation-redeem` and inherits `HttpControlClient.recordProviderRejection`,
  `fetchRoutingCandidates` and `redeemAttestation`. `rpcServer.ts` registers only
  nine routes, none of them these three. Probe H2: all three return 404, while a
  registered route returns 401 to a non-mTLS caller.
- The relay awaits `recordProviderRejection` before asking for the next attempt
  (`controlPlane.ts:2449-2452`). That call writes the failover signal that
  `lastAttemptWasBadRequest` reads (`controlPlane.ts:2990`).
  `recordProviderRejection` swallows the non-2xx (`controlClient.ts:112-117`).
  So in node mode a `provider_bad_request` no longer stops fallback, and the
  same prompt is sent to additional providers.
- `/models` missing breaks automatic routing (`RoutingCatalogCache` cold
  failure), and `/attestation-redeem` missing breaks attestation, in node mode.
- **Fix:** add the three routes before any node activation. Provider-rejection
  must be presenter-bound: run `assertContentRequestFallbackTx` (or a
  completion check) for the request before writing failover signals. The legacy
  route (`routes/internal/control.ts:155`) has no ownership check at all, so a
  shared-relay-token holder can also write failover signals for strict requests.
  Extend that route's check to refuse strict rows.
- Already gated: node-scoped catalog is listed in the checkpoint's
  "before production" list. The fallback-suppression loss is not mentioned there.

### M1. Node-mode abort-before-create writes no cancellation tombstone — PROVED

- The relay relies on abort writing a tombstone even when the reservation does
  not exist yet (`routes/chat.ts:780-785`, "closing the abort-before-create
  race"). In node mode, `ControlPlane.abort` first runs
  `assertRequestAuthority` (`controlPlane.ts:3178`). With a presenter and no
  origin row, `assertContentRequestCompletionTx` refuses
  (`requestOwnership.ts:157-158`) **before** `cancelAuthorization`.
- Probe M1 (disposable Redis): a legacy abort sets `authz:<id>` to `canceled`. A
  node relay abort for a not-yet-reserved id is refused, leaves `authz:<id>`
  null, and a later reservation for that id succeeds and stays `reserved`.
- Mitigation that exists: `rpcServer.ts:72-83` compensates when the
  *authorize* connection itself closes or exceeds 5 seconds. Nothing covers a
  relay that aborts on another connection while authorize is still running and
  keeps the authorize socket open. If compensation is refused (lease lost, see
  G1), the strict hold strands, because strict rows are excluded from the sweep.
  No committed test covers either path.
- **Fix:** let a presenter abort for a request with no reservation write the
  tombstone, scoped to that presenter. For example, record
  `canceled:<nodeId>:<generation>` and have `admitContentRequestTx` refuse a
  tombstoned id. Alternatively, write the tombstone before the authority
  precheck when no reservation row exists. Add tests for both the
  separate-connection abort and the server-side timeout compensation.

### M2. Transport timing makes non-idempotent RPC outcomes ambiguous — source review

- The client and server authorize deadlines are both 5 seconds
  (`rpcClient.ts:107` default `timeoutMs`; `rpcServer.ts:72`). The server's
  compensation only fires if it observes the close before authorize returns. A
  response written just before the client timer fires is discarded by the
  relay without server-side compensation, leaving only the relay's later abort
  (see M1).
- The client agent's idle `timeout: 30_000` (`rpcClient.ts:60`) equals the
  server's `keepAliveTimeout: 30_000` (`rpcServer.ts:44`). A pooled socket can
  be reused just as the server closes it. Node's https agent then fails the
  request with a reset, which `post` maps to `content_rpc_unavailable` for
  settle, capture and authorize alike. A reset before any byte is written is
  safe to retry; one after write is not. The transport cannot tell them apart
  and has no retry.
- **Fix:** keep the client agent idle timeout below the server keep-alive (for
  example 20s against 30s). Give authorize a client timeout above the server
  deadline (for example server 5s, client 8s) so the server's compensation path
  wins. Classify errors as `before_write` or `may_have_dispatched`, the way the
  SDK's retained transport does, so the relay knows when an abort is required.

### M3. A node can adopt a same-account pending LEGACY reservation — PROVED

- The relay chooses `requestId` (`rpcSchemas.ts:70`). `reserveBalance`'s
  idempotent branch (`billing.ts:285-304`) accepts an existing `reserved` row for
  the same account and API key and then runs `admitContentRequestTx`, which
  inserts an origin onto a legacy row that has no provider attempt yet.
- Probe M3: after a legacy reservation, a node `reserveBalance` with the same id
  creates the origin. The owning legacy relay's `finalizeInferenceReservation`
  then refuses with `content_request_owner_mismatch`, and the row is excluded
  from the legacy sweep (`billing.ts:1450`), so the hold strands.
- Exploitability is limited. It needs the same account and key, a valid ticket
  for that account, knowledge of a live legacy request id, and the coexistence
  window. It still breaks the checkpoint statement that legacy work stays
  separate.
- **Fix:** in the idempotent branch, refuse `nodeAdmission` when the existing
  row has no origin. Only an already node-owned row may be re-admitted, and only
  by the same node.

### M4. Old-binary coexistence is enforced only in application code — PROVED

- Default privileges (`grants.sql:41-42`) leave `anonrouter_rpc` with
  `UPDATE/DELETE` on `billing.inference_reservations`. Probe M4: the RPC role
  directly finalizes a strict row (`status='released'`). A pre-140 control
  binary, or its 15-minute sweep, running against the migrated database would
  settle, abort or ceiling-capture strict reservations without any ownership
  check.
- The checkpoint documents the rollout ordering. Nothing in the database fails
  closed if that ordering is violated.
- **Fix:** add a `BEFORE UPDATE` trigger on `billing.inference_reservations`.
  For rows with a `content_node_request_origins` entry, require a transaction
  marker that only ownership-aware code sets (for example
  `SET LOCAL anonrouter.content_authority = 'v140'`, set alongside the existing
  authority check). This does not stop a compromised role, but it makes an old
  binary refuse instead of silently acting.

### M5. A lost dispatch acknowledgment can capture the full ceiling for no provider work — source review

- `authorizeProviderAttempt` consumes the grant (`GETDEL`) and commits the
  provider fence (`provider_attempt_started_at`) before responding. If the
  response is lost, the worker never calls the provider, which is correct: no
  replay. The relay's later abort, without the `providerRejected` attestation,
  then captures the reserved ceiling (`billing.ts`, `captureAuthorizedCeiling`
  in `finalizeInferenceReservation`).
- This is the existing conservative policy ("disconnecting early never yields
  free provider work"). The new mTLS hop and M2 make it a reachable customer
  overcharge on a transport failure.
- **Owner decision:** whether a measured worker may attest "fence acknowledged
  but provider never contacted" (analogous to `providerRejected`) so the abort
  releases. Until then, record this as an accepted financial risk, not a
  silent one.

### Lower findings

- **L1 Authorize failure compensation can be refused.** On a post-reservation
  error, authorize releases with the node presenter (`controlPlane.ts:2329-2337`)
  and swallows refusal with `.catch(() => undefined)`. If the boot's lease
  lapsed mid-authorize, the strict hold strands. This is gated by the documented
  missing reconciliation controller. It should at least be counted and alerted,
  not swallowed silently.
- **L2 Fence capability = DoS.** `UPDATE (fenced_at)` (`grants.sql:53`) lets the
  RPC role fence any scope, irreversibly (availability only). That is
  acceptable, but document it.
- **L3 Non-terminal state reversals are permitted by the trigger.** Migration
  140 lines 92-94 forbid only leaving terminal states. A controller-role update
  could take `draining` back to `admitted` (reopening new work during a
  retirement) or `admitted` back to `quarantined`. Restrict transitions to the
  intended graph.
- **L4 Receipt before finalize.** `ControlPlane.settle` records the opaque
  receipt in its own committed transaction, then finalizes in a second one. If
  finalize is refused in between (completion deadline crossed, lease lost), a
  15-minute receipt exists for an unsettled reservation. Move both into one
  transaction, or record the receipt after finalization.
- **L5 Redis lifetimes shorter than the node window.** Authorization state and
  provider plan TTLs are 20 minutes (`controlPlane.ts:171,184`), while a node
  completion window may be 60 minutes. After 20 minutes the same `requestId` can
  be re-authorized with a new ticket through the idempotent branch, and a fresh
  attempt-0 grant is minted. The attempt fence keeps this to one provider
  attempt, so it fails closed, but the second ticket is consumed. Prefer
  refusing re-authorization of an existing node-owned row.
- **L6 Key selection label.** The worker always sends `deploymentId: "primary"`
  (`rpcClient.ts:126`), and Venice key selection keys on it. This is gated as
  "provider generation-aware key selection".

## Verified as holding (no finding)

- Presenter forgery: `WeakSet` registration only after real mTLS SPKI plus capability resolution. The presenter is resolved per request, so a keep-alive connection cannot reuse a fenced scope.
- Relay/worker separation: the role is fixed per route.
- One-use grants: `GETDEL` happens before any check, so a mismatch consumes the grant. Boot, generation, deadline and ordinal come only from the grant; a race allows exactly one winner (committed test).
- Strict/legacy separation for settle, capture, abort, delivery, receipt, route mutation, the legacy wallet helper and the shared-token dispatch path.
- Strictly increasing attempt ordinals, with immutable attempts, owners and origins. Request versus completion deadlines are enforced inside the fence.
- `finalizeInferenceReservation` checks authority before every idempotent return.
- Lock order reservation → node (share) → scope (share) is consistent with the lifecycle writers; no cycle was found.
- Retirement blocks on any `reserved` origin, including pre-dispatch holds.
- The strict sweep exclusion prevents ceiling capture of live streams.
- Client side: TLS 1.3 only, no session tickets, SPKI pinned at handshake and rechecked on the actual socket before the bearer is written, no redirects, response size bounded.

## Gated, unfinished work (already listed in the checkpoint)

These are not counted as bypasses:

- reconciliation for failed, expired or revoked strict holds;
- bootstrap first-heartbeat and source-authentication integration (H1 shows the
  database must enforce it too);
- listener custody and network path;
- node-scoped catalog and singleton jobs;
- generation-aware key selection;
- request-abort and idle-heartbeat behavior;
- native guest qualification;
- two-node switch, rollback and settlement acceptance.

## Coordination

The guest (`ctx_a93c938d4c80`) and bootstrap (`ctx_b9f46f4e27fa`) dispatches
had already completed, so their mailboxes were unreadable and no reply was
possible. H1's first-heartbeat consequence should go to whoever owns bootstrap
integration next.

## Appendix: probe bodies

Appended in the scratch copy after line 121 of
`tests/integration/content-node-ownership.test.ts`, which supplies the
fixture. Each probe asserts that the defect EXISTS.

```ts
it("PROBE H1: anonrouter_rpc can extend a lease without bound, roll back the heartbeat sequence and fabricate a first heartbeat",async()=>{
  await db.query(`UPDATE providers.content_nodes SET heartbeat_sequence=7 WHERE node_id=$1`,[nodes[1]]);
  const forged=await rpcDb.query(`UPDATE providers.content_nodes
    SET lease_until=clock_timestamp()+interval '10 years',heartbeat_sequence=0 WHERE node_id=$1
    RETURNING lease_until,heartbeat_sequence`,[nodes[1]]);
  expect(forged.rowCount).toBe(1);
  expect(Number(forged.rows[0].heartbeat_sequence)).toBe(0);
  expect(new Date(forged.rows[0].lease_until).getTime()).toBeGreaterThan(Date.now()+9*365*86_400_000);
  expect(await expireContentNodeLeases(db)).not.toContain(nodes[1]);
  expect(await heartbeatContentNode(db,await presenter(3),1)).toBeTruthy();
  // fresh admitted boot without first heartbeat: presenter refused, then forged by anonrouter_rpc
  // ...insert node + relay scope as controller...
  await expect(presenter(scopes.length-1)).rejects.toMatchObject({code:"content_node_unauthorized"});
  const fabricated=await rpcDb.query(`UPDATE providers.content_nodes SET last_heartbeat_at=clock_timestamp(),
    lease_until=clock_timestamp()+interval '1 day' WHERE node_id=$1`,[fresh]);
  expect(fabricated.rowCount).toBe(1);
  expect((await presenter(scopes.length-1)).nodeId).toBe(fresh);
});

it("PROBE M3: a node adopts a pending same-account LEGACY reservation by reusing its requestId",async()=>{
  const id=randomUUID();
  await reserveBalance(db,accountId,.1,id,{context:context()});
  await reserveBalance(db,accountId,.1,id,{nodeAdmission:{presenter:await presenter(3),completionWindowMs:600_000},context:context()});
  expect((await db.query(`SELECT node_id FROM billing.content_node_request_origins WHERE request_id=$1`,[id])).rows[0].node_id).toBe(nodes[1]);
  await expect(finalizeInferenceReservation(db,{requestId:id,outcome:"abort"})).rejects.toMatchObject({code:"content_request_owner_mismatch"});
});

it("PROBE M4: the RPC database role (and so any pre-140 binary using it) can finalize a strict row directly",async()=>{
  const id=await reservation(1);
  const direct=await rpcDb.query(`UPDATE billing.inference_reservations SET status='released',finalized_at=now()
    WHERE request_id=$1 AND status='reserved'`,[id]);
  expect(direct.rowCount).toBe(1);
});

it("PROBE H2: node-mode client paths provider-rejection/models/attestation-redeem have no mTLS route",async()=>{
  const server=await buildContentNodeRpcServer({db,controlPlane:{} as ControlPlane,tls:{key,cert,ca:cert},
    completionWindowMs:600_000,requestWindowMs:600_000});
  for(const path of ["/internal/control/provider-rejection","/internal/control/models","/internal/control/attestation-redeem"]){
    expect((await server.inject({method:"POST",url:path,payload:{}})).statusCode).toBe(404);
  }
  expect((await server.inject({method:"POST",url:"/internal/control/abort",payload:{}})).statusCode).toBe(401);
  await server.close();
});

it.runIf(disposableRedisAvailable())("PROBE M1: node-mode abort before the reservation exists writes no cancellation tombstone",async()=>{
  // ControlPlane over rpcDb + disposable Redis, rate limiter stubbed
  await control.abort({requestId:legacyId,status:"failed",latencyMs:0});
  expect(await fixture.redis.get(`authz:${legacyId}`)).toBe("canceled");
  await expect(control.abort({requestId:nodeId,status:"failed",latencyMs:0},relay)).rejects.toMatchObject({code:"content_request_owner_mismatch"});
  expect(await fixture.redis.get(`authz:${nodeId}`)).toBeNull();
  await reserveBalance(db,accountId,.1,nodeId,{nodeAdmission:{presenter:relay,completionWindowMs:600_000},context:context()});
  expect((await db.query(`SELECT status FROM billing.inference_reservations WHERE request_id=$1`,[nodeId])).rows[0].status).toBe("reserved");
});
```

Result in the scratch copy: `review-probes.test.ts` 5/5 passed (2.4 s);
`content-node-ownership.test.ts` 13/13 passed.
