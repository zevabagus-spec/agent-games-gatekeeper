// End-to-end test harness: boots the real server (dummy HMAC secret, temp
// store) and replays spec-shaped envelopes over HTTP.
//
// Coverage:
//   - health check + preflight shape and response signatures
//   - HMAC verification: tamper / wrong secret / missing / garbage -> 401;
//     hex, base64, and `sha256=`-prefixed MACs accepted
//   - valid task -> APPROVE + Groth16 proof verified locally with snarkjs
//     against verification_key.json, and public signals cross-checked
//     against independently recomputed field values (including
//     Poseidon(taskId, salt) via circomlibjs)
//   - boundary-valid task (balance == minimum, amount == max_transfer,
//     current_block == expiry_block - 1) -> APPROVE
//   - case-insensitive VK compare (0X + uppercase hex) -> APPROVE
//   - all six trap types -> correct REJECT + reason_code, with verified
//     proofs (PROOF_REUSED carries no proof)
//   - idempotent redelivery returns the cached body byte-for-byte
//   - malformed envelope / past deadline -> REJECT INVALID_TASK
//   - unknown type -> 400, invalid JSON -> 400, unknown path -> 404
//   - persistence: seen-set + cache survive a server restart
//   - response-time measurement on every case (60s platform deadline)
//
// Field conversions are reimplemented here independently (not imported
// from src/) so the tests validate the server's conversions instead of
// restating them. Each case runs independently; the exit code is non-zero
// if any case fails.
//
// Usage: npm test   (builds first)

import { spawn } from "node:child_process";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { createServer as createNetServer } from "node:net";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, "..");
const VK = JSON.parse(readFileSync(join(PROJECT_ROOT, "verification_key.json"), "utf8"));

// Dummy secret for local tests only. Clearly marked; never a real secret.
const TEST_SECRET = Buffer.from("test-only-dummy-hmac-secret", "utf8");
const WRONG_SECRET = Buffer.from("test-only-WRONG-hmac-secret", "utf8");
const SIG_HEADER = "x-agent-games-signature";

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => ((x % P) + P) % P;
const sha256BigInt = (s) => BigInt("0x" + createHash("sha256").update(s, "utf8").digest("hex"));

function fieldFromHash(value) {
  const s = String(value).trim();
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
  if (/^[0-9a-fA-F]{64}$/.test(s)) return modP(BigInt("0x" + s));
  return modP(sha256BigInt(s));
}
function fieldFromNumeric(value) {
  if (typeof value === "number") return modP(BigInt(value));
  const s = String(value).trim();
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
  return modP(BigInt(s));
}
function fieldFromTaskId(taskId) {
  const s = String(taskId).trim();
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) return modP(BigInt(s));
  if (/^-?\d+$/.test(s)) return modP(BigInt(s));
  return modP(sha256BigInt(s));
}
function saltFor(taskId) {
  const mac = createHmac("sha256", TEST_SECRET).update("gatekeeper-salt:" + String(taskId), "utf8").digest();
  return modP(BigInt("0x" + mac.toString("hex")));
}

const VK_A = "0x" + "ab".repeat(32);
const VK_B = "0x" + "cd".repeat(32);
const ADDR_A = "0x" + "11".repeat(20);
const ADDR_B = "0x" + "22".repeat(20);

let txCounter = 0;
function uniqueProofTx() {
  txCounter += 1;
  return "0x" + txCounter.toString(16).padStart(64, "0");
}

function makeTask(taskId, inputOverrides = {}, envelopeOverrides = {}) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "round",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 120_000).toISOString(),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: "1000",
      public_balance: "5000",
      expiry_block: 2000,
      current_block: 1000,
      recipient: ADDR_A,
      condition_recipient: ADDR_A,
      amount: "500",
      max_transfer: "1000",
      proof_tx: uniqueProofTx(),
      ...inputOverrides,
    },
    ...envelopeOverrides,
  };
}

// ---------------------------------------------------------------------------
// Runner plumbing
// ---------------------------------------------------------------------------

const results = [];
let poseidon;

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

function signHex(secret, bodyText) {
  return createHmac("sha256", secret).update(bodyText, "utf8").digest("hex");
}

function responseSignatureValid(rawText, headerValue) {
  if (typeof headerValue !== "string") return false;
  const expected = Buffer.from(signHex(TEST_SECRET, rawText), "hex");
  let candidate;
  try {
    candidate = Buffer.from(headerValue.trim(), "hex");
  } catch {
    return false;
  }
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

async function freePort() {
  return new Promise((resolvePort, reject) => {
    const srv = createNetServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolvePort(port));
    });
    srv.on("error", reject);
  });
}

async function startServer(port, storePath) {
  const child = spawn("node", [join(PROJECT_ROOT, "dist", "index.js")], {
    env: {
      ...process.env,
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET.toString("utf8"),
      SEEN_STORE_PATH: storePath,
      PORT: String(port),
      HOST: "127.0.0.1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (d) => (output += d.toString()));
  child.stderr.on("data", (d) => (output += d.toString()));
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 15000;
  for (;;) {
    try {
      const res = await fetch(`${base}/agent`);
      if (res.status === 200) break;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`server did not come up on ${base}\n${output}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return {
    child,
    base,
    output: () => output,
    stop: () =>
      new Promise((resolveStop) => {
        child.once("exit", resolveStop);
        child.kill("SIGTERM");
        setTimeout(() => {
          child.kill("SIGKILL");
          resolveStop();
        }, 5000).unref();
      }),
  };
}

async function postRaw(base, path, rawText, secret, encoding = "hex") {
  const started = Date.now();
  const mac = createHmac("sha256", secret).update(rawText, "utf8").digest();
  let header;
  if (encoding === "hex") header = mac.toString("hex");
  else if (encoding === "base64") header = mac.toString("base64");
  else if (encoding === "sha256-prefix") header = "sha256=" + mac.toString("hex");
  else throw new Error(`unknown encoding ${encoding}`);
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", [SIG_HEADER]: header },
    body: rawText,
  });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get(SIG_HEADER), ms: Date.now() - started };
}

async function postJson(base, obj, secret = TEST_SECRET, encoding = "hex") {
  const raw = JSON.stringify(obj);
  const r = await postRaw(base, "/agent", raw, secret, encoding);
  let json = null;
  try {
    json = JSON.parse(r.text);
  } catch {
    // leave null; assertions will report
  }
  return { ...r, json, raw };
}

function expectedPublicSignals(task, decision) {
  const taskId = String(task.task_id);
  const input = task.input;
  const f = {
    taskId: fieldFromTaskId(taskId),
    registeredVkHash: fieldFromHash(input.registered_vk),
    proofVkHash: fieldFromHash(input.proof_vk),
    minimum: fieldFromNumeric(input.minimum),
    publicBalance: fieldFromNumeric(input.public_balance),
    expiryBlock: fieldFromNumeric(input.expiry_block),
    currentBlock: fieldFromNumeric(input.current_block),
    recipient: fieldFromHash(input.recipient),
    conditionRecipient: fieldFromHash(input.condition_recipient),
    amount: fieldFromNumeric(input.amount),
    maxTransfer: fieldFromNumeric(input.max_transfer),
  };
  const salt = saltFor(taskId);
  // EMPIRICAL circuit layout (verified by direct fullProve + Poseidon
  // candidates; see README "Circuit findings"): the first public signal is
  // Poseidon([salt, taskId]) — salt FIRST — and taskId is the LAST public
  // signal, not the second. The public spec's stated order
  // ([Poseidon(taskId, salt), taskId, ...]) does not match the artifact.
  const hash = poseidon.F.toString(poseidon([salt, f.taskId]));
  return [
    hash,
    f.registeredVkHash.toString(),
    f.proofVkHash.toString(),
    f.minimum.toString(),
    f.publicBalance.toString(),
    f.expiryBlock.toString(),
    f.currentBlock.toString(),
    f.recipient.toString(),
    f.conditionRecipient.toString(),
    f.amount.toString(),
    f.maxTransfer.toString(),
    decision === "APPROVE" ? "1" : "0",
    f.taskId.toString(),
  ];
}

async function assertVerifiedProof(name, task, body, decision) {
  assert(body.proof, `${name}: missing proof`);
  assert(body.proof.protocol === "groth16", `${name}: protocol != groth16`);
  assert(body.proof.curve === "bn128", `${name}: curve != bn128`);
  // snarkjs native proof shape: 3-element pi_a/pi_c (affine + homogeneous
  // "1"), 3-pair pi_b (last pair ["1","0"]).
  assert(Array.isArray(body.proof.pi_a) && body.proof.pi_a.length === 3 && body.proof.pi_a[2] === "1", `${name}: bad pi_a`);
  assert(
    Array.isArray(body.proof.pi_b) &&
      body.proof.pi_b.length === 3 &&
      body.proof.pi_b[2][0] === "1" &&
      body.proof.pi_b[2][1] === "0",
    `${name}: bad pi_b`
  );
  assert(Array.isArray(body.proof.pi_c) && body.proof.pi_c.length === 3 && body.proof.pi_c[2] === "1", `${name}: bad pi_c`);
  assert(Array.isArray(body.public_signals) && body.public_signals.length === 13, `${name}: expected 13 public signals`);
  const expected = expectedPublicSignals(task, decision);
  assert(
    JSON.stringify(body.public_signals) === JSON.stringify(expected),
    `${name}: public signals mismatch.\n  got:      ${JSON.stringify(body.public_signals)}\n  expected: ${JSON.stringify(expected)}`
  );
  const ok = await groth16.verify(VK, body.public_signals, body.proof);
  assert(ok, `${name}: snarkjs groth16.verify returned false`);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

async function main() {
  poseidon = await buildPoseidon();
  const workdir = mkdtempSync(join(tmpdir(), "gatekeeper-test-"));
  const storePath = join(workdir, "seen.json");
  const port = await freePort();
  const ctx = { server: await startServer(port, storePath) };
  const base = () => ctx.server.base;

  const validTask = makeTask("task-valid-001");
  let validBodyText = null;

  const cases = [];
  const test = (name, fn) => cases.push({ name, fn });

  test("GET /agent health check (signed)", async () => {
    const started = Date.now();
    const res = await fetch(`${base()}/agent`);
    const text = await res.text();
    const ms = Date.now() - started;
    const json = JSON.parse(text);
    assert(res.status === 200, `health status ${res.status}`);
    assert(json.ok === true && json.protocolVersion === "v1", "health shape");
    assert(responseSignatureValid(text, res.headers.get(SIG_HEADER)), "health signature");
    return ms;
  });

  test("preflight shape + response signature", async () => {
    const r = await postJson(base(), { type: "agent-games.preflight.v1" });
    assert(r.status === 200, `preflight status ${r.status}: ${r.text}`);
    assert(r.json.ok === true && r.json.protocolVersion === "v1", "preflight shape");
    assert(responseSignatureValid(r.text, r.sig), "preflight signature");
    return r.ms;
  });

  test("HMAC base64 encoding accepted", async () => {
    const r = await postJson(base(), { type: "agent-games.preflight.v1" }, TEST_SECRET, "base64");
    assert(r.status === 200, `base64 MAC status ${r.status}`);
    return r.ms;
  });

  test("HMAC sha256= prefix accepted", async () => {
    const r = await postJson(base(), { type: "agent-games.preflight.v1" }, TEST_SECRET, "sha256-prefix");
    assert(r.status === 200, `sha256= prefix status ${r.status}`);
    return r.ms;
  });

  test("tampered body -> 401", async () => {
    const raw = JSON.stringify({ type: "agent-games.preflight.v1" });
    const tampered = raw.replace("preflight", "preflighX");
    const mac = signHex(TEST_SECRET, raw);
    const res = await fetch(`${base()}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json", [SIG_HEADER]: mac },
      body: tampered,
    });
    await res.text();
    assert(res.status === 401, `tampered status ${res.status}`);
    return null;
  });

  test("wrong HMAC secret -> 401", async () => {
    const r = await postJson(base(), { type: "agent-games.preflight.v1" }, WRONG_SECRET);
    assert(r.status === 401, `wrong secret status ${r.status}`);
    return r.ms;
  });

  test("missing signature -> 401", async () => {
    const res = await fetch(`${base()}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "agent-games.preflight.v1" }),
    });
    await res.text();
    assert(res.status === 401, `missing signature status ${res.status}`);
    return null;
  });

  test("garbage signature -> 401", async () => {
    const res = await fetch(`${base()}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json", [SIG_HEADER]: "not-a-signature!!!" },
      body: JSON.stringify({ type: "agent-games.preflight.v1" }),
    });
    await res.text();
    assert(res.status === 401, `garbage signature status ${res.status}`);
    return null;
  });

  test("valid task -> APPROVE + verified proof", async () => {
    const r = await postJson(base(), validTask);
    assert(r.status === 200, `valid task status ${r.status}: ${r.text}`);
    assert(r.json.decision === "APPROVE", `decision ${r.json.decision}`);
    assert(r.json.reason_code === "VALID_CONDITION", `reason ${r.json.reason_code}`);
    assert(r.json.proof_tx === validTask.input.proof_tx, "proof_tx echo");
    assert(responseSignatureValid(r.text, r.sig), "task response signature");
    await assertVerifiedProof("valid task", validTask, r.json, "APPROVE");
    assert(r.ms < 60000, `response took ${r.ms}ms`);
    validBodyText = r.text;
    return r.ms;
  });

  test("boundary-valid task -> APPROVE + verified proof", async () => {
    const task = makeTask(12345, {
      public_balance: "1000",
      amount: "1000",
      current_block: 1999,
    });
    const r = await postJson(base(), task);
    assert(r.status === 200, `boundary status ${r.status}: ${r.text}`);
    assert(r.json.decision === "APPROVE", `boundary decision ${r.json.decision}`);
    assert(r.json.reason_code === "VALID_CONDITION", `boundary reason ${r.json.reason_code}`);
    await assertVerifiedProof("boundary task", task, r.json, "APPROVE");
    return r.ms;
  });

  test("case-insensitive VK (0X + uppercase) -> APPROVE", async () => {
    const task = makeTask("task-vk-case", { proof_vk: "0X" + "AB".repeat(32) });
    const r = await postJson(base(), task);
    assert(r.status === 200, `vk-case status ${r.status}: ${r.text}`);
    assert(r.json.decision === "APPROVE", `vk-case decision ${r.json.decision}`);
    await assertVerifiedProof("vk-case task", task, r.json, "APPROVE");
    return r.ms;
  });

  test("trap VK_SUBSTITUTION -> REJECT + verified proof", async () => {
    const task = makeTask("task-trap-vk", { proof_vk: VK_B });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `vk trap decision ${r.json.decision}`);
    assert(r.json.reason_code === "VK_SUBSTITUTION", `vk trap reason ${r.json.reason_code}`);
    await assertVerifiedProof("vk trap", task, r.json, "REJECT");
    return r.ms;
  });

  test("trap THRESHOLD_MISMATCH -> REJECT + verified proof", async () => {
    const task = makeTask("task-trap-threshold", { public_balance: "999" });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `threshold decision ${r.json.decision}`);
    assert(r.json.reason_code === "THRESHOLD_MISMATCH", `threshold reason ${r.json.reason_code}`);
    await assertVerifiedProof("threshold trap", task, r.json, "REJECT");
    return r.ms;
  });

  test("trap EXPIRED_CONDITION -> REJECT + verified proof", async () => {
    const task = makeTask("task-trap-expired", { current_block: 2000 });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `expired decision ${r.json.decision}`);
    assert(r.json.reason_code === "EXPIRED_CONDITION", `expired reason ${r.json.reason_code}`);
    await assertVerifiedProof("expired trap", task, r.json, "REJECT");
    return r.ms;
  });

  test("trap RECIPIENT_MISMATCH -> REJECT + verified proof", async () => {
    const task = makeTask("task-trap-recipient", { recipient: ADDR_B });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `recipient decision ${r.json.decision}`);
    assert(r.json.reason_code === "RECIPIENT_MISMATCH", `recipient reason ${r.json.reason_code}`);
    await assertVerifiedProof("recipient trap", task, r.json, "REJECT");
    return r.ms;
  });

  test("trap AMOUNT_OVERFLOW -> REJECT + verified proof", async () => {
    const task = makeTask("task-trap-amount", { amount: "1001" });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `amount decision ${r.json.decision}`);
    assert(r.json.reason_code === "AMOUNT_OVERFLOW", `amount reason ${r.json.reason_code}`);
    await assertVerifiedProof("amount trap", task, r.json, "REJECT");
    return r.ms;
  });

  test("trap PROOF_REUSED -> REJECT, no proof", async () => {
    const task = makeTask("task-trap-reuse", { proof_tx: validTask.input.proof_tx });
    const r = await postJson(base(), task);
    assert(r.json.decision === "REJECT", `reuse decision ${r.json.decision}`);
    assert(r.json.reason_code === "PROOF_REUSED", `reuse reason ${r.json.reason_code}`);
    assert(!("proof" in r.json), "reuse response must omit proof");
    assert(!("public_signals" in r.json), "reuse response must omit public_signals");
    assert(r.json.proof_tx === validTask.input.proof_tx, "reuse proof_tx echo");
    return r.ms;
  });

  test("redelivery returns cached response byte-for-byte", async () => {
    assert(validBodyText !== null, "valid task case must run first");
    const r = await postJson(base(), validTask);
    assert(r.status === 200, `redelivery status ${r.status}`);
    assert(r.text === validBodyText, "redelivery body differs from cached response");
    assert(r.json.decision === "APPROVE", "redelivery must not be misread as reuse");
    return r.ms;
  });

  test("same task_id + mutated envelope -> cached response", async () => {
    assert(validBodyText !== null, "valid task case must run first");
    const mutated = makeTask("task-valid-001", { amount: "999999" });
    const r = await postJson(base(), mutated);
    assert(r.text === validBodyText, "same task_id must return cached response");
    return r.ms;
  });

  test("malformed envelope -> REJECT INVALID_TASK", async () => {
    const task = makeTask("task-malformed");
    delete task.input.amount;
    const r = await postJson(base(), task);
    assert(r.status === 200, `malformed status ${r.status}`);
    assert(r.json.decision === "REJECT", `malformed decision ${r.json.decision}`);
    assert(r.json.reason_code === "INVALID_TASK", `malformed reason ${r.json.reason_code}`);
    assert(r.json.proof_tx === task.input.proof_tx, "malformed proof_tx echo");
    return r.ms;
  });

  test("past deadline -> REJECT INVALID_TASK", async () => {
    const task = makeTask(
      "task-past-deadline",
      {},
      { deadline_at: new Date(Date.now() - 60000).toISOString() }
    );
    const r = await postJson(base(), task);
    assert(r.status === 200, `past-deadline status ${r.status}`);
    assert(r.json.decision === "REJECT", `past-deadline decision ${r.json.decision}`);
    assert(r.json.reason_code === "INVALID_TASK", `past-deadline reason ${r.json.reason_code}`);
    return r.ms;
  });

  test("unknown envelope type -> 400", async () => {
    const r = await postJson(base(), { type: "agent-games.unknown.v9" });
    assert(r.status === 400, `unknown type status ${r.status}`);
    return r.ms;
  });

  test("invalid JSON -> 400", async () => {
    const r = await postRaw(base(), "/agent", "{not json", TEST_SECRET);
    assert(r.status === 400, `invalid json status ${r.status}`);
    return r.ms;
  });

  test("unknown path -> 404", async () => {
    const res = await fetch(`${base()}/nope`);
    await res.text();
    assert(res.status === 404, `unknown path status ${res.status}`);
    return null;
  });

  test("seen-set + cache survive restart", async () => {
    assert(validBodyText !== null, "valid task case must run first");
    await ctx.server.stop();
    ctx.server = await startServer(port, storePath);
    const r1 = await postJson(base(), validTask);
    assert(r1.text === validBodyText, "cache did not survive restart");
    const reuseAfterRestart = makeTask("task-reuse-after-restart", { proof_tx: validTask.input.proof_tx });
    const r2 = await postJson(base(), reuseAfterRestart);
    assert(r2.json.reason_code === "PROOF_REUSED", `seen-set did not survive restart: ${r2.json.reason_code}`);
    return r1.ms + r2.ms;
  });

  // Run all cases independently.
  for (const { name, fn } of cases) {
    const started = Date.now();
    try {
      const ms = await fn();
      results.push({ name, ok: true, ms: ms ?? Date.now() - started });
      console.log(`PASS  ${name}  (${ms ?? Date.now() - started}ms)`);
    } catch (err) {
      results.push({ name, ok: false, detail: err.message });
      console.log(`FAIL  ${name}\n      ${err.message.split("\n").join("\n      ")}`);
    }
  }

  const serverOutput = ctx.server.output();
  await ctx.server.stop();
  rmSync(workdir, { recursive: true, force: true });

  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);
  const timings = results.map((r) => r.ms).filter((ms) => typeof ms === "number");
  const maxMs = timings.length ? Math.max(...timings) : 0;
  console.log(`\n${passed}/${results.length} passed. Slowest case: ${maxMs}ms (platform deadline 60000ms).`);
  if (failed.length > 0) {
    console.log("--- server output (tail) ---");
    console.log(serverOutput.slice(-3000));
  }
  // Exit explicitly: undici keep-alive sockets from fetch() can hold the
  // event loop open long after the suite finishes.
  process.exit(failed.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
