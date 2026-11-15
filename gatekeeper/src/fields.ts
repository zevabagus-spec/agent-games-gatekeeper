// Field-element conversions for the BN128 scalar field.
//
// The gatekeeper circuit sees every input as a field element. These helpers
// convert envelope values to field elements exactly the way the circuit's
// checks assume, so the off-circuit decision logic mirrors the circuit,
// boundaries included:
//
// - Numeric values (balances, blocks, amounts): parsed as integers
//   (decimal string, 0x hex string, or safe JSON number) and reduced mod p.
//   Comparisons in the decision logic run on the reduced values, i.e. on
//   exactly what the circuit compares.
// - Hash-like values (verification keys, recipients): hex strings parsed as
//   integers mod p. Equality is therefore field-element equality, which
//   subsumes the spec's case-insensitive hex compare and also treats
//   leading-zero variants as equal, exactly as the circuit does. Non-hex
//   strings fall back to SHA-256 (same conversion on both sides, so
//   equality is still decided consistently).
// - task_id: numeric/hex ids are used directly mod p; free-form ids are
//   hashed with SHA-256 first, then reduced mod p.
// - salt: HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p, so a
//   redelivery reproduces identical witness inputs deterministically.

import { createHash, createHmac } from "node:crypto";

export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function modP(x: bigint): bigint {
  const r = x % BN128_PRIME;
  return r >= 0n ? r : r + BN128_PRIME;
}

function isHexString(s: string): boolean {
  return /^0[xX][0-9a-fA-F]+$/.test(s);
}

function isDecimalString(s: string): boolean {
  return /^-?\d+$/.test(s);
}

function isBareHex32(s: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(s);
}

/** SHA-256 of UTF-8 input, interpreted as a big-endian integer. */
export function sha256ToBigInt(data: string): bigint {
  const digest = createHash("sha256").update(data, "utf8").digest();
  return BigInt("0x" + digest.toString("hex"));
}

/**
 * Parse a numeric envelope value (minimum, balances, blocks, amounts) into
 * a field element. Throws FieldParseError on anything unparseable.
 */
export function parseNumericField(value: unknown, name: string): bigint {
  if (typeof value === "bigint") return modP(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new FieldParseError(`${name}: number is not a safe integer`);
    }
    return modP(BigInt(value));
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (isHexString(s)) return modP(BigInt(s));
    if (isDecimalString(s)) return modP(BigInt(s));
  }
  throw new FieldParseError(`${name}: cannot parse numeric value ${JSON.stringify(value)}`);
}

/**
 * Parse a hash-like envelope value (verification keys, recipient addresses)
 * into a field element. Hex input (0x-prefixed, or a bare 64-hex-char
 * digest) is parsed directly; anything else is SHA-256 hashed so that two
 * equal non-hex values still compare equal. Throws on non-string/non-number
 * input.
 */
export function parseHashField(value: unknown, name: string): bigint {
  if (typeof value === "bigint") return modP(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new FieldParseError(`${name}: number is not a safe integer`);
    }
    return modP(BigInt(value));
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (isHexString(s)) return modP(BigInt(s));
    if (isBareHex32(s)) return modP(BigInt("0x" + s));
    if (s.length > 0) return modP(sha256ToBigInt(s));
  }
  throw new FieldParseError(`${name}: cannot parse hash value ${JSON.stringify(value)}`);
}

/** task_id -> field element: numeric/hex ids direct mod p, otherwise SHA-256 mod p. */
export function taskIdToField(taskId: string): bigint {
  const s = taskId.trim();
  if (isHexString(s)) return modP(BigInt(s));
  if (isDecimalString(s)) return modP(BigInt(s));
  return modP(sha256ToBigInt(s));
}

/** Deterministic salt: HMAC-SHA256(secret, "gatekeeper-salt:" + task_id) mod p. */
export function deriveSalt(secret: Buffer, taskId: string): bigint {
  const mac = createHmac("sha256", secret).update("gatekeeper-salt:" + taskId, "utf8").digest();
  return modP(BigInt("0x" + mac.toString("hex")));
}

export class FieldParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FieldParseError";
  }
}
