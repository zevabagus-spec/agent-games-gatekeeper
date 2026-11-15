// Persistent seen-set + response cache.
//
// The store survives restarts: it is a single JSON file (path via
// SEEN_STORE_PATH, default <project>/data/seen.json) holding
//   - seenProofTx: proof_tx values of evaluated tasks (reuse detection)
//   - responses: task_id -> exact raw response body (idempotent redelivery)
//
// Writes are synchronous and atomic (temp file + rename) so a crash can
// never leave a half-written store, and so concurrent requests in the
// single-threaded server cannot interleave a read-modify-write.
//
// proof_tx keys are normalized (trim + lowercase) so the reuse check is
// case-insensitive, matching how hashes are compared elsewhere. task_id
// keys are used verbatim.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

interface StoredState {
  version: 1;
  seenProofTx: string[];
  responses: Record<string, string>;
}

export function normalizeProofTx(proofTx: string): string {
  return proofTx.trim().toLowerCase();
}

export class SeenStore {
  private readonly filePath: string;
  private readonly seen = new Set<string>();
  private readonly responses = new Map<string, string>();

  constructor(filePath: string) {
    this.filePath = filePath;
    if (existsSync(filePath)) {
      const raw = readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw) as StoredState;
      if (parsed && Array.isArray(parsed.seenProofTx)) {
        for (const tx of parsed.seenProofTx) this.seen.add(tx);
      }
      if (parsed && parsed.responses && typeof parsed.responses === "object") {
        for (const [k, v] of Object.entries(parsed.responses)) {
          if (typeof v === "string") this.responses.set(k, v);
        }
      }
    }
  }

  hasSeen(proofTx: string): boolean {
    return this.seen.has(normalizeProofTx(proofTx));
  }

  getCached(taskId: string): string | undefined {
    return this.responses.get(taskId);
  }

  /**
   * Record one evaluated task: mark its proof_tx as seen (unless it is
   * already there) and cache its exact response body, in a single persist.
   * Call only after a task has been fully evaluated (decision + proof, or a
   * PROOF_REUSED / INVALID_TASK outcome). Proof-generation failures must
   * NOT be recorded, so a redelivery can re-evaluate.
   */
  recordEvaluation(taskId: string, proofTx: string | null, responseBody: string): void {
    if (proofTx !== null) this.seen.add(normalizeProofTx(proofTx));
    this.responses.set(taskId, responseBody);
    this.persist();
  }

  /** Cache a response without touching the seen-set (envelope-level failures). */
  cacheOnly(taskId: string, responseBody: string): void {
    this.responses.set(taskId, responseBody);
    this.persist();
  }

  private persist(): void {
    const state: StoredState = {
      version: 1,
      seenProofTx: [...this.seen].sort(),
      responses: Object.fromEntries(this.responses),
    };
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;
    writeFileSync(tmpPath, JSON.stringify(state, null, 2), "utf8");
    renameSync(tmpPath, this.filePath);
  }
}
