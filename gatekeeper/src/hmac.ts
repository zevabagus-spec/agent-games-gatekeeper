// HMAC-SHA256 request verification and response signing.
//
// The platform signs the RAW request body; verification happens over the
// exact bytes received, before any JSON parsing. Responses are signed the
// same way: HMAC-SHA256 hex over the raw response body, in the
// `x-agent-games-signature` header.
//
// Verification is defensive about encodings: the header value may be hex or
// base64, with an optional `sha256=` prefix. Comparison is constant-time
// (crypto.timingSafeEqual) for every candidate encoding.

import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

export function signBody(secret: Buffer, body: Buffer): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function decodeCandidates(value: string): Buffer[] {
  const out: Buffer[] = [];
  const trimmed = value.trim();
  const stripped = trimmed.replace(/^sha256=/i, "");
  // Hex candidate: even-length hex string.
  if (/^[0-9a-fA-F]+$/.test(stripped) && stripped.length % 2 === 0) {
    try {
      out.push(Buffer.from(stripped, "hex"));
    } catch {
      // fall through
    }
  }
  // Base64 candidate: strict-ish check, then decode and re-encode to confirm
  // the input was canonical base64 (avoids Buffer.from silently accepting
  // garbage).
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(stripped) && stripped.length % 4 === 0) {
    try {
      const decoded = Buffer.from(stripped, "base64");
      if (decoded.length > 0 && decoded.toString("base64") === stripped) {
        out.push(decoded);
      }
    } catch {
      // fall through
    }
  }
  return out;
}

export function verifySignature(
  secret: Buffer,
  body: Buffer,
  headerValue: string | string[] | undefined
): boolean {
  if (typeof headerValue !== "string") return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  for (const candidate of decodeCandidates(headerValue)) {
    if (candidate.length !== expected.length) continue;
    if (timingSafeEqual(candidate, expected)) return true;
  }
  return false;
}
