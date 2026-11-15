// Groth16 proof generation against the official gatekeeper circuit.
//
// Witness inputs use the signal names recovered by probing the WASM
// (scripts/probe-signals.mjs): 13 scalar inputs, 12 public + the private
// salt. The circuit asserts decision == AND of the five field checks, so
// proving fails loudly if the off-circuit decision ever disagrees with the
// circuit — that failure is surfaced to the caller, which fails closed.

import * as snarkjs from "snarkjs";
import type { CircuitFields, Decision } from "./decision.js";

export interface GeneratedProof {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: "groth16";
    curve: "bn128";
  };
  publicSignals: string[];
  proveMs: number;
}

export async function generateProof(
  wasmPath: string,
  zkeyPath: string,
  fields: CircuitFields,
  decision: Decision,
  salt: bigint
): Promise<GeneratedProof> {
  const inputs: Record<string, string> = {
    taskId: fields.taskId.toString(),
    registeredVkHash: fields.registeredVkHash.toString(),
    proofVkHash: fields.proofVkHash.toString(),
    minimum: fields.minimum.toString(),
    publicBalance: fields.publicBalance.toString(),
    expiryBlock: fields.expiryBlock.toString(),
    currentBlock: fields.currentBlock.toString(),
    recipient: fields.recipient.toString(),
    conditionRecipient: fields.conditionRecipient.toString(),
    amount: fields.amount.toString(),
    maxTransfer: fields.maxTransfer.toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(),
  };
  const started = Date.now();
  // snarkjs argument order is (input, wasm, zkey) — mirroring the CLI.
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, wasmPath, zkeyPath);
  return {
    proof: {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: publicSignals.map(String),
    proveMs: Date.now() - started,
  };
}
