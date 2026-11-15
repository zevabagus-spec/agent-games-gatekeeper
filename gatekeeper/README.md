# Proof Gatekeeper Agent — zkVerify Agent Games

An original implementation of a Proof Gatekeeper agent for the
[Agent Games by zkVerify](https://agentgames.zkverify.io) competition,
written from the public spec on the official site. No competitor code was
used. The circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`)
are the official platform files.

The platform POSTs signed task envelopes to a public HTTPS endpoint. This
agent verifies the HMAC, makes a deterministic APPROVE/REJECT decision,
generates a Groth16 proof locally with snarkjs against the official
gatekeeper circuit, and returns a signed JSON response within the 60-second
deadline.

## Architecture

```
POST /agent ──► HMAC verify (raw body, constant-time)
        │
        ├── type agent-games.preflight.v1 ──► { ok: true, protocolVersion: "v1" }
        │
        └── type agent-games.proof-gatekeeper.v1
                │
                ├── response cache hit (same task_id) ──► cached body, byte-for-byte
                ├── envelope validation / deadline ──► REJECT INVALID_TASK on failure
                ├── decision rules (VK → reuse → threshold → expiry → recipient → amount)
                ├── PROOF_REUSED ──► REJECT, no proof (documented)
                ├── snarkjs groth16.fullProve ──► proof + 13 public signals
                └── record seen proof_tx + cache response (atomic JSON store)
```

Plain `node:http`, no web framework — raw-body handling stays exact.
TypeScript, strict mode. Dependencies: `snarkjs` (proving), `circomlibjs`
(Poseidon cross-checks in tests only).

| File | Purpose |
| --- | --- |
| `src/index.ts` | Entrypoint; env config; refuses to start without a secret |
| `src/server.ts` | HTTP handling, routing, signing, idempotency, soft budget |
| `src/decision.ts` | Envelope parsing + decision rules in spec check order |
| `src/fields.ts` | BN128 field conversions, task-id hashing, salt derivation |
| `src/prover.ts` | snarkjs `fullProve` wrapper (input order: input, wasm, zkey) |
| `src/hmac.ts` | HMAC-SHA256 verify (hex/base64, optional `sha256=`) + sign |
| `src/store.ts` | Atomic JSON seen-set + response cache |
| `scripts/probe-signals.mjs` | Recovers circuit input signal names from the WASM |
| `test/e2e.test.mjs` | Full end-to-end harness (boots the real server) |
| `verification_key.json` | Extracted from the zkey (`snarkjs zkey export verificationkey`) |

## Protocol details

- **Endpoint path:** `POST /agent` (a trailing slash is also accepted).
  `GET /agent` is a health check returning
  `{ ok: true, service: "proof-gatekeeper", protocolVersion: "v1" }`.
- **Request authentication:** header `x-agent-games-signature`, HMAC-SHA256
  over the raw request body, verified **before** JSON parsing. Hex and
  base64 MAC encodings are accepted, with an optional `sha256=` prefix.
  Comparison is constant-time. Mismatch → HTTP 401.
- **Response signing:** every response carries HMAC-SHA256 hex over its raw
  body in the same header.
- **Preflight:** envelope type `agent-games.preflight.v1` →
  `{ ok: true, protocolVersion: "v1" }`, signed.
- **Task envelope:** type `agent-games.proof-gatekeeper.v1` with `task_id`,
  `mode`, `issued_at`, `deadline_at`, and `input` (`registered_vk`,
  `proof_vk`, `minimum`, `public_balance`, `expiry_block`, `current_block`,
  `recipient`, `condition_recipient`, `amount`, `max_transfer`, `proof_tx`).
- **Decision rules** (first failing check wins):
  `VK_SUBSTITUTION` → `PROOF_REUSED` → `THRESHOLD_MISMATCH` →
  `EXPIRED_CONDITION` → `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW`, else
  `APPROVE` / `VALID_CONDITION`. Equality and comparisons run on field
  elements (values reduced mod the BN128 prime), exactly as the circuit
  computes them — this subsumes case-insensitive hex comparison and
  leading-zero variants, boundaries included.
- **Response shape:**
  `{ decision, reason_code, proof: { pi_a, pi_b, pi_c, protocol: "groth16", curve: "bn128" }, public_signals: [13 strings], proof_tx }`.
  The proof is snarkjs's native format (3-element `pi_a`/`pi_c`,
  3-pair `pi_b`). `PROOF_REUSED` responses omit `proof`/`public_signals`.
  `proof_tx` echoes the task input; no Kurier submission in v1 (optional).
- **Idempotency:** a redelivered `task_id` returns the cached response
  body byte-for-byte without re-evaluation and without touching the
  seen-set. Concurrent duplicate deliveries share one in-flight evaluation.
- **Seen-set:** `proof_tx` is recorded only for evaluated tasks (a
  redelivery never double-counts). Keys are normalized (trim + lowercase).
- **Fail closed:** malformed envelopes, past deadlines, internal errors,
  and proof-generation failures → `REJECT`. `INVALID_TASK` is used for
  envelope-level failures and proof-generation failures. Proof-generation
  failures carry no proof and are **not** cached and **not** marked seen,
  so a redelivery can re-evaluate instead of cementing a transient failure.
  Unparseable JSON and unknown envelope types → HTTP 400 (no task context
  exists to form a decision response).
- **Deadlines:** the platform deadline is 60s. A soft internal budget
  (default 55s) answers fail-closed rather than timing out silently.
  Measured warm proving time is ~0.3–0.4s (first cold prove ~1s).
- **Salt:** `HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p`, so
  redelivery reproduces identical witness inputs deterministically.
- **task_id → field element:** numeric/hex ids are used directly mod p;
  free-form ids are SHA-256 hashed, then reduced mod p.

## Circuit findings (verified against the artifacts, not taken on trust)

`npm run probe` queries the WASM's `getInputSignalSize` hash oracle
(FNV-1a of the signal name, the same mechanism `circom_runtime` uses) and
recovers exactly 13 scalar inputs:

```
taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
expiryBlock, currentBlock, recipient, conditionRecipient, amount,
maxTransfer, decision, salt
```

Circom 2.2.3, BN128 prime confirmed, witness size 647, `getInputSize` 13.
All 23 decoy/variant names probed (snake_case, alternate casings, etc.)
are absent.

**Two discrepancies with the public spec's prose were found by direct
`fullProve` experiments and are reflected in the test harness:**

1. **Public-signal order.** The spec prose says
   `[Poseidon(taskId, salt), then the 12 public inputs in the order above]`.
   The artifact actually emits `taskId` **last**:
   `[hash, registeredVkHash, proofVkHash, minimum, publicBalance,
   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
   maxTransfer, decision, taskId]`.
2. **Hash argument order.** The first public signal is
   `Poseidon([salt, taskId])` — salt first — not `Poseidon(taskId, salt)`.
   Verified by comparing `circomlibjs` Poseidon candidates against real
   proofs.

The server is unaffected by both: it returns snarkjs's `publicSignals`
verbatim, and the platform re-verifies against the verification key. Any
independent verifier must use the empirical layout above.

## Environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | — | Issued at registration. Never commit it. |
| `PORT` | no | `3000` | |
| `HOST` | no | `0.0.0.0` | |
| `SEEN_STORE_PATH` | no | `<project>/data/seen.json` | Seen-set + cache; must survive restarts |
| `CIRCUIT_WASM_PATH` | no | `../circuits/gatekeeper.wasm` | |
| `CIRCUIT_ZKEY_PATH` | no | `../circuits/gatekeeper_final.zkey` | |
| `SOFT_BUDGET_MS` | no | `55000` | Fail-closed budget inside the 60s deadline |
| `MAX_BODY_BYTES` | no | `1048576` | Request body cap |

Copy `.env.example` to `.env` for local runs (`.env` is gitignored). In
production, prefer real environment variables / a secret manager.

## Run

```sh
npm install
npm run build
AGENT_GAMES_HMAC_SECRET='<issued secret>' npm start
# or: npm run dev   (tsx watch mode)
```

Health check: `curl http://localhost:3000/agent`.

## Tests

```sh
npm test
```

Boots the real server on a scratch port with a dummy secret and a temp
store, then replays spec-shaped envelopes: HMAC roundtrip + tamper /
wrong-secret / missing / garbage → 401; hex/base64/`sha256=` MACs;
preflight shape + signature; valid + boundary-valid tasks → APPROVE with
proofs verified locally via `snarkjs groth16.verify` against
`verification_key.json` and public signals cross-checked against
independently recomputed field values (including Poseidon via
`circomlibjs`); all six trap types → correct `REJECT` + `reason_code`
with verified proofs (`PROOF_REUSED` without proof); byte-identical
redelivery; malformed/past-deadline → `INVALID_TASK`; 400/404 paths;
seen-set + cache surviving a restart; per-case timings against the 60s
deadline. 25/25 pass; slowest case ~1s (cold first prove), warm proves
~0.3–0.4s.

```sh
npm run probe   # recover + print the circuit's input signal names
```

## Register / preflight (done separately, not by this repo)

1. Deploy this server behind public HTTPS (TLS termination by the hosting
   platform or a reverse proxy).
2. Register the public endpoint URL (path `/agent`) on
   [agentgames.zkverify.io](https://agentgames.zkverify.io) for the Proof
   Gatekeeper track and copy the issued HMAC secret into
   `AGENT_GAMES_HMAC_SECRET`.
3. The platform sends a `agent-games.preflight.v1` envelope to confirm the
   endpoint; this server answers it automatically. Verify the deployment
   answers the health check and a signed preflight before a round opens.

## Spec ambiguities and how they were resolved

- **Equality semantics:** the spec says "case-insensitive hex compare" for
  VKs/recipients. Implemented as field-element equality (hex parsed mod p),
  which matches the circuit exactly and additionally normalizes leading
  zeros and `0X` prefixes.
- **Comparisons on reduced values:** balances/blocks/amounts are compared
  after reduction mod p, mirroring the circuit. (In practice all values are
  far below p, so this only matters for adversarial inputs.)
- **Non-hex hash values:** hashed with SHA-256 (same conversion both
  sides), so equality stays consistent; unparseable numeric values make
  the envelope `INVALID_TASK`.
- **`deadline_at` formats:** ISO strings, numeric strings, and numbers
  (seconds when < 1e12, else milliseconds) are accepted; unparseable
  values → `INVALID_TASK`. The cache is checked before the deadline, so a
  redelivery always returns the cached response (idempotency wins over
  the deadline check for already-evaluated tasks).
- **`mode`:** carried in the envelope but no mode-specific behavior is
  specified; all modes are evaluated identically.
- **Proof-failure reason code:** the spec lists no dedicated code, so
  proof-generation failures return `REJECT` / `INVALID_TASK` with no
  proof, uncached, unmarked-seen.
- **Unparseable JSON / unknown types:** HTTP 400, since no task context
  exists to form a decision response.
- **GET responses:** signed like everything else, for uniformity.
