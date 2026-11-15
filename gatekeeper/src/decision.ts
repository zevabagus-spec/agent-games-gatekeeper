// Envelope parsing and the APPROVE/REJECT decision rules.
//
// APPROVE only if ALL of the following hold, checked in this order (the
// first failing check determines the reason_code):
//   1. proof_vk == registered_vk            -> VK_SUBSTITUTION
//   2. proof_tx not seen before             -> PROOF_REUSED
//   3. public_balance >= minimum            -> THRESHOLD_MISMATCH
//   4. current_block < expiry_block         -> EXPIRED_CONDITION
//   5. recipient == condition_recipient     -> RECIPIENT_MISMATCH
//   6. amount <= max_transfer               -> AMOUNT_OVERFLOW
// Otherwise APPROVE with reason_code VALID_CONDITION.
//
// Equality and comparisons run on field elements (values reduced mod the
// BN128 prime), exactly as the circuit computes them, so the decision logic
// mirrors the circuit's asserted AND of the five field checks, boundaries
// included. The reuse check (2) is the one check the circuit cannot make —
// it is enforced off-circuit via the persistent seen-set, and PROOF_REUSED
// responses carry no proof, as specified.
//
// Envelope-level failures (missing/mistyped fields, unparseable values,
// past deadline) produce REJECT / INVALID_TASK, never an unproven APPROVE.

import {
  FieldParseError,
  parseHashField,
  parseNumericField,
  taskIdToField,
} from "./fields.js";

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "PROOF_REUSED"
  | "THRESHOLD_MISMATCH"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  | "INVALID_TASK";

export interface GatekeeperInput {
  registered_vk: unknown;
  proof_vk: unknown;
  minimum: unknown;
  public_balance: unknown;
  expiry_block: unknown;
  current_block: unknown;
  recipient: unknown;
  condition_recipient: unknown;
  amount: unknown;
  max_transfer: unknown;
  proof_tx: unknown;
}

export interface ParsedEnvelope {
  taskId: string;
  mode: unknown;
  issuedAt: unknown;
  deadlineAt: unknown;
  input: GatekeeperInput;
}

/** Field elements for the circuit witness, in circuit input order. */
export interface CircuitFields {
  taskId: bigint;
  registeredVkHash: bigint;
  proofVkHash: bigint;
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: bigint;
  conditionRecipient: bigint;
  amount: bigint;
  maxTransfer: bigint;
}

export interface Evaluation {
  decision: Decision;
  reasonCode: ReasonCode;
  fields: CircuitFields;
  proofTx: string;
}

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

const REQUIRED_INPUT_FIELDS = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
] as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function parseEnvelope(body: unknown): ParsedEnvelope {
  if (!isRecord(body)) throw new EnvelopeError("envelope is not a JSON object");
  const rawTaskId = body["task_id"];
  if (typeof rawTaskId !== "string" && typeof rawTaskId !== "number") {
    throw new EnvelopeError("task_id missing or not a string/number");
  }
  const taskId = String(rawTaskId).trim();
  if (taskId.length === 0) throw new EnvelopeError("task_id is empty");
  if (!isRecord(body["input"])) throw new EnvelopeError("input missing or not an object");
  const input = body["input"];
  for (const field of REQUIRED_INPUT_FIELDS) {
    if (!(field in input) || input[field] === undefined || input[field] === null) {
      throw new EnvelopeError(`input.${field} is missing`);
    }
  }
  return {
    taskId,
    mode: body["mode"],
    issuedAt: body["issued_at"],
    deadlineAt: body["deadline_at"],
    input: input as unknown as GatekeeperInput,
  };
}

/**
 * Parse deadline_at into epoch milliseconds, or null when absent.
 * Accepts ISO strings, numeric strings, and numbers (seconds when < 1e12,
 * milliseconds otherwise). Throws EnvelopeError when present but
 * unparseable.
 */
export function parseDeadline(deadlineAt: unknown): number | null {
  if (deadlineAt === undefined || deadlineAt === null) return null;
  if (typeof deadlineAt === "number") {
    if (!Number.isFinite(deadlineAt)) throw new EnvelopeError("deadline_at is not finite");
    return deadlineAt < 1e12 ? deadlineAt * 1000 : deadlineAt;
  }
  if (typeof deadlineAt === "string") {
    const s = deadlineAt.trim();
    if (/^-?\d+(\.\d+)?$/.test(s)) {
      const n = Number(s);
      return n < 1e12 ? n * 1000 : n;
    }
    const ms = Date.parse(s);
    if (!Number.isNaN(ms)) return ms;
  }
  throw new EnvelopeError("deadline_at is unparseable");
}

function fieldsOf(input: GatekeeperInput, taskId: string): CircuitFields {
  try {
    return {
      taskId: taskIdToField(taskId),
      registeredVkHash: parseHashField(input.registered_vk, "registered_vk"),
      proofVkHash: parseHashField(input.proof_vk, "proof_vk"),
      minimum: parseNumericField(input.minimum, "minimum"),
      publicBalance: parseNumericField(input.public_balance, "public_balance"),
      expiryBlock: parseNumericField(input.expiry_block, "expiry_block"),
      currentBlock: parseNumericField(input.current_block, "current_block"),
      recipient: parseHashField(input.recipient, "recipient"),
      conditionRecipient: parseHashField(input.condition_recipient, "condition_recipient"),
      amount: parseNumericField(input.amount, "amount"),
      maxTransfer: parseNumericField(input.max_transfer, "max_transfer"),
    };
  } catch (err) {
    if (err instanceof FieldParseError) throw new EnvelopeError(err.message);
    throw err;
  }
}

/**
 * Evaluate the decision rules. `isSeen` answers whether proof_tx was
 * already recorded for a previously evaluated task. Check order is
 * VK, reuse, threshold, expiry, recipient, amount.
 */
export function evaluate(envelope: ParsedEnvelope, isSeen: (proofTx: string) => boolean): Evaluation {
  const fields = fieldsOf(envelope.input, envelope.taskId);
  const rawProofTx = envelope.input.proof_tx;
  if (typeof rawProofTx !== "string" && typeof rawProofTx !== "number") {
    throw new EnvelopeError("input.proof_tx must be a string");
  }
  const proofTx = String(rawProofTx);

  let reasonCode: ReasonCode | null = null;
  if (fields.proofVkHash !== fields.registeredVkHash) {
    reasonCode = "VK_SUBSTITUTION";
  } else if (isSeen(proofTx)) {
    reasonCode = "PROOF_REUSED";
  } else if (fields.publicBalance < fields.minimum) {
    reasonCode = "THRESHOLD_MISMATCH";
  } else if (fields.currentBlock >= fields.expiryBlock) {
    reasonCode = "EXPIRED_CONDITION";
  } else if (fields.recipient !== fields.conditionRecipient) {
    reasonCode = "RECIPIENT_MISMATCH";
  } else if (fields.amount > fields.maxTransfer) {
    reasonCode = "AMOUNT_OVERFLOW";
  }

  return {
    decision: reasonCode === null ? "APPROVE" : "REJECT",
    reasonCode: reasonCode ?? "VALID_CONDITION",
    fields,
    proofTx,
  };
}
