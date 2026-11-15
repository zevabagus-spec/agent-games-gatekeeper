// HTTP server: raw-body HMAC verification, preflight, task evaluation,
// signed responses, idempotent redelivery, fail-closed error handling.
//
// Protocol (from the public spec):
//   GET  /agent -> 200 health check JSON.
//   POST /agent with header x-agent-games-signature (HMAC-SHA256 over the
//   raw body) and a JSON envelope:
//     type agent-games.preflight.v1            -> { ok: true, protocolVersion: "v1" }
//     type agent-games.proof-gatekeeper.v1     -> decision response (see below)
//   HMAC mismatch -> 401. Unparseable JSON / unknown type -> 400.
//   Every response is signed with HMAC-SHA256 hex over its raw body.
//
// Decision response:
//   { decision, reason_code, proof, public_signals, proof_tx }
//   PROOF_REUSED responses omit proof/public_signals. Envelope-level
//   failures (malformed input, past deadline, proof-generation failure)
//   return REJECT / INVALID_TASK; proof-generation failures carry no proof
//   and are not cached, so a redelivery can re-evaluate.
//
// Redelivery: a task_id already in the response cache returns the cached
// body byte-for-byte without re-evaluation (and without touching the
// seen-set). Concurrent duplicate deliveries share one in-flight
// evaluation. The platform's 60s response deadline is guarded by a soft
// internal budget (default 55s): if evaluation ever exceeds it, the
// handler answers REJECT / INVALID_TASK instead of timing out silently.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { deriveSalt } from "./fields.js";
import { SIGNATURE_HEADER, signBody, verifySignature } from "./hmac.js";
import { SeenStore } from "./store.js";
import {
  EnvelopeError,
  evaluate,
  parseDeadline,
  parseEnvelope,
  type ReasonCode,
} from "./decision.js";
import { generateProof, type GeneratedProof } from "./prover.js";

export interface GatekeeperConfig {
  hmacSecret: Buffer;
  wasmPath: string;
  zkeyPath: string;
  store: SeenStore;
  /** Soft internal budget in ms; the platform deadline is 60s. */
  softBudgetMs: number;
  /** Max request body size in bytes (envelopes are small). */
  maxBodyBytes: number;
}

const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PROTOCOL_VERSION = "v1";

interface TaskResponseBody {
  decision: "APPROVE" | "REJECT";
  reason_code: ReasonCode;
  proof?: GeneratedProof["proof"];
  public_signals?: string[];
  proof_tx: string;
}

function log(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...fields }));
}

function truncate(value: string, max = 18): string {
  return value.length > max ? value.slice(0, max) + "…" : value;
}

export function createGatekeeperServer(config: GatekeeperConfig): Server {
  const inflight = new Map<string, Promise<string>>();

  function sendSigned(res: ServerResponse, status: number, bodyObject: unknown): void {
    const body = Buffer.from(JSON.stringify(bodyObject), "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": body.length,
      [SIGNATURE_HEADER]: signBody(config.hmacSecret, body),
    });
    res.end(body);
  }

  function sendSignedRaw(res: ServerResponse, status: number, rawBody: string): void {
    const body = Buffer.from(rawBody, "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": body.length,
      [SIGNATURE_HEADER]: signBody(config.hmacSecret, body),
    });
    res.end(body);
  }

  async function readBody(req: IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of req) {
      const buf = chunk as Buffer;
      total += buf.length;
      if (total > config.maxBodyBytes) {
        throw new Error("body_too_large");
      }
      chunks.push(buf);
    }
    return Buffer.concat(chunks);
  }

  function invalidTaskBody(proofTx: string): TaskResponseBody {
    return { decision: "REJECT", reason_code: "INVALID_TASK", proof_tx: proofTx };
  }

  /** Evaluate one task envelope and return the exact response body string. */
  async function handleTask(envelopeBody: unknown, startedAt: number): Promise<string> {
    // Parse the envelope. Envelope-level failure -> INVALID_TASK, cached
    // when a task_id is available so redelivery is deterministic.
    let envelope;
    try {
      envelope = parseEnvelope(envelopeBody);
    } catch (err) {
      if (err instanceof EnvelopeError) {
        const proofTx = extractProofTx(envelopeBody);
        const body = JSON.stringify(invalidTaskBody(proofTx));
        const taskId = extractTaskId(envelopeBody);
        if (taskId !== null) config.store.cacheOnly(taskId, body);
        log({ event: "invalid_task", reason: err.message, proof_tx: truncate(proofTx) });
        return body;
      }
      throw err;
    }
    const { taskId } = envelope;

    // Idempotency: cached response wins, before any re-evaluation and
    // before the deadline check.
    const cached = config.store.getCached(taskId);
    if (cached !== undefined) {
      log({ event: "redelivery_cached", task_id: truncate(taskId) });
      return cached;
    }

    // Past deadline -> INVALID_TASK (envelope-level failure).
    let deadlineMs: number | null;
    try {
      deadlineMs = parseDeadline(envelope.deadlineAt);
    } catch (err) {
      if (err instanceof EnvelopeError) {
        const body = JSON.stringify(invalidTaskBody(extractProofTx(envelopeBody)));
        config.store.cacheOnly(taskId, body);
        log({ event: "invalid_task", task_id: truncate(taskId), reason: err.message });
        return body;
      }
      throw err;
    }
    if (deadlineMs !== null && Date.now() > deadlineMs) {
      const body = JSON.stringify(invalidTaskBody(extractProofTx(envelopeBody)));
      config.store.cacheOnly(taskId, body);
      log({ event: "invalid_task", task_id: truncate(taskId), reason: "past_deadline" });
      return body;
    }

    // Evaluate the decision rules.
    let evaluation;
    try {
      evaluation = evaluate(envelope, (tx) => config.store.hasSeen(tx));
    } catch (err) {
      if (err instanceof EnvelopeError) {
        const body = JSON.stringify(invalidTaskBody(extractProofTx(envelopeBody)));
        config.store.cacheOnly(taskId, body);
        log({ event: "invalid_task", task_id: truncate(taskId), reason: err.message });
        return body;
      }
      throw err;
    }
    const { decision, reasonCode, fields, proofTx } = evaluation;

    // PROOF_REUSED carries no proof (documented) and needs no proving.
    if (reasonCode === "PROOF_REUSED") {
      const body = JSON.stringify({
        decision,
        reason_code: reasonCode,
        proof_tx: proofTx,
      } satisfies TaskResponseBody);
      config.store.recordEvaluation(taskId, proofTx, body);
      log({
        event: "evaluated",
        task_id: truncate(taskId),
        decision,
        reason_code: reasonCode,
        ms: Date.now() - startedAt,
      });
      return body;
    }

    // Generate the Groth16 proof. Failure -> fail closed: REJECT /
    // INVALID_TASK, no proof, NOT cached and NOT marked seen, so a
    // redelivery re-evaluates instead of cementing a transient failure.
    let generated: GeneratedProof;
    try {
      generated = await generateProof(
        config.wasmPath,
        config.zkeyPath,
        fields,
        decision,
        deriveSalt(config.hmacSecret, taskId)
      );
    } catch (err) {
      log({
        event: "prove_failed",
        task_id: truncate(taskId),
        decision,
        reason_code: reasonCode,
        error: err instanceof Error ? err.message : String(err),
      });
      return JSON.stringify(invalidTaskBody(proofTx));
    }

    const body = JSON.stringify({
      decision,
      reason_code: reasonCode,
      proof: generated.proof,
      public_signals: generated.publicSignals,
      proof_tx: proofTx,
    } satisfies TaskResponseBody);
    config.store.recordEvaluation(taskId, proofTx, body);
    log({
      event: "evaluated",
      task_id: truncate(taskId),
      decision,
      reason_code: reasonCode,
      prove_ms: generated.proveMs,
      ms: Date.now() - startedAt,
    });
    return body;
  }

  async function handlePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let rawBody: Buffer;
    try {
      rawBody = await readBody(req);
    } catch {
      sendSigned(res, 413, { ok: false, error: "body_too_large" });
      return;
    }

    // HMAC over the RAW body, before parsing.
    if (!verifySignature(config.hmacSecret, rawBody, req.headers[SIGNATURE_HEADER])) {
      sendSigned(res, 401, { ok: false, error: "invalid_signature" });
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendSigned(res, 400, { ok: false, error: "invalid_json" });
      return;
    }

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      sendSigned(res, 400, { ok: false, error: "invalid_envelope" });
      return;
    }
    const type = (parsed as Record<string, unknown>)["type"];

    if (type === PREFLIGHT_TYPE) {
      sendSigned(res, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
      return;
    }
    if (type !== TASK_TYPE) {
      sendSigned(res, 400, { ok: false, error: "unknown_type" });
      return;
    }

    // Soft budget: answer fail-closed rather than blowing the 60s deadline.
    const startedAt = Date.now();
    const taskIdHint = extractTaskId(parsed);
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      log({ event: "soft_budget_exceeded", task_id: taskIdHint ? truncate(taskIdHint) : null });
      sendSigned(res, 200, invalidTaskBody(extractProofTx(parsed)));
    }, config.softBudgetMs);
    timer.unref();

    // Share one evaluation between concurrent duplicate deliveries.
    let promise: Promise<string> | undefined;
    if (taskIdHint !== null) {
      promise = inflight.get(taskIdHint);
      if (promise === undefined) {
        promise = handleTask(parsed, startedAt).finally(() => {
          if (taskIdHint !== null) inflight.delete(taskIdHint);
        });
        inflight.set(taskIdHint, promise);
      }
    } else {
      promise = handleTask(parsed, startedAt);
    }

    try {
      const body = await promise;
      if (settled) return; // soft-budget answer already sent
      settled = true;
      clearTimeout(timer);
      sendSignedRaw(res, 200, body);
    } catch (err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      log({ event: "internal_error", error: err instanceof Error ? err.message : String(err) });
      sendSigned(res, 200, invalidTaskBody(extractProofTx(parsed)));
    }
  }

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://localhost");
        const path = url.pathname;
        if (path !== "/agent" && path !== "/agent/") {
          sendSigned(res, 404, { ok: false, error: "not_found" });
          return;
        }
        if (req.method === "GET") {
          sendSigned(res, 200, {
            ok: true,
            service: "proof-gatekeeper",
            protocolVersion: PROTOCOL_VERSION,
          });
          return;
        }
        if (req.method === "POST") {
          await handlePost(req, res);
          return;
        }
        sendSigned(res, 405, { ok: false, error: "method_not_allowed" });
      } catch (err) {
        if (!res.headersSent) {
          sendSigned(res, 500, { ok: false, error: "internal_error" });
        }
        log({ event: "handler_error", error: err instanceof Error ? err.message : String(err) });
      }
    })();
  });

  return server;
}

/** Best-effort proof_tx extraction for fail-closed responses. */
function extractProofTx(body: unknown): string {
  if (typeof body === "object" && body !== null && !Array.isArray(body)) {
    const input = (body as Record<string, unknown>)["input"];
    if (typeof input === "object" && input !== null && !Array.isArray(input)) {
      const tx = (input as Record<string, unknown>)["proof_tx"];
      if (typeof tx === "string") return tx;
      if (typeof tx === "number") return String(tx);
    }
  }
  return "";
}

/** Best-effort task_id extraction for in-flight dedup and logging. */
function extractTaskId(body: unknown): string | null {
  if (typeof body === "object" && body !== null && !Array.isArray(body)) {
    const id = (body as Record<string, unknown>)["task_id"];
    if (typeof id === "string" && id.trim().length > 0) return id.trim();
    if (typeof id === "number") return String(id);
  }
  return null;
}
