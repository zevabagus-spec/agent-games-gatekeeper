// Probe the gatekeeper circuit WASM to recover its input signal names.
//
// Circom 2.x WASM modules do not embed signal names. Input signals are
// addressed by the FNV-1a 64-bit hash of the name, split into two 32-bit
// halves, via the exported `getInputSignalSize(hMSB, hLSB)` oracle, which
// returns the signal size (>= 0) or a negative value when the hash matches
// no input signal. This is the exact mechanism circom_runtime's
// WitnessCalculatorCircom2 uses (see node_modules/circom_runtime/js/
// witness_calculator.js). We query that oracle with candidate names and
// report which ones exist, so the signal-name claim is evidenced by the
// artifact itself rather than taken on trust.
//
// Usage: node scripts/probe-signals.mjs [path/to/gatekeeper.wasm]

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.argv[2] || resolve(__dirname, "../../circuits/gatekeeper.wasm");

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fnvHash(str) {
  const uint64Max = 2n ** 64n;
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= 0x100000001b3n;
    hash %= uint64Max;
  }
  return hash.toString(16).padStart(16, "0");
}

function hashHalves(name) {
  const h = fnvHash(name);
  return [parseInt(h.slice(0, 8), 16), parseInt(h.slice(8, 16), 16)];
}

async function main() {
  const code = readFileSync(wasmPath);
  const memory = new WebAssembly.Memory({ initial: 1024 });
  const stub = () => {};
  const { instance } = await WebAssembly.instantiate(code, {
    env: { memory },
    runtime: {
      printDebug: stub,
      exceptionHandler: (code) => {
        throw new Error(`wasm exceptionHandler code=${code}`);
      },
      printErrorMessage: stub,
      writeBufferMessage: stub,
      showSharedRWMemory: stub,
      error: stub,
      log: stub,
      logGetSignal: stub,
      logSetSignal: stub,
      logStartComponent: stub,
      logFinishComponent: stub,
    },
  });

  const ex = instance.exports;
  console.log(`WASM: ${wasmPath}`);
  console.log(`exports: ${Object.keys(ex).sort().join(", ")}`);
  if (typeof ex.getVersion === "function") {
    console.log(
      `circom version: ${ex.getVersion()}.${ex.getMinorVersion?.() ?? "?"}.${
        ex.getPatchVersion?.() ?? "?"
      }`
    );
  }

  // Prime check via getRawPrime + shared RW memory.
  // circom_runtime reads arr[n32-1-j] = readSharedRWMemory(j), i.e. limb j is
  // the (n32-1-j)-th most significant limb.
  const n32 = ex.getFieldNumLen32();
  ex.getRawPrime();
  const limbs = [];
  for (let j = 0; j < n32; j++) limbs.push(BigInt(ex.readSharedRWMemory(j) >>> 0));
  let prime = 0n;
  for (let j = 0; j < n32; j++) {
    prime = (prime << 32n) | limbs[n32 - 1 - j];
  }
  console.log(`field prime matches BN128: ${prime === BN128_PRIME}`);
  console.log(`witness size: ${ex.getWitnessSize()}`);
  console.log(`total input signals (getInputSize): ${ex.getInputSize()}`);
  console.log("");

  const candidates = [
    // Expected names (from the public spec).
    "taskId",
    "registeredVkHash",
    "proofVkHash",
    "minimum",
    "publicBalance",
    "expiryBlock",
    "currentBlock",
    "recipient",
    "conditionRecipient",
    "amount",
    "maxTransfer",
    "decision",
    "salt",
    // Variants / decoys that must NOT match.
    "task_id",
    "taskID",
    "registered_vk_hash",
    "registeredVKHash",
    "registeredVk",
    "proof_vk_hash",
    "proofVKHash",
    "min",
    "threshold",
    "public_balance",
    "balance",
    "expiry_block",
    "expiry",
    "current_block",
    "receiver",
    "condition_recipient",
    "transferAmount",
    "max_transfer",
    "maxAmount",
    "approve",
    "foo",
    "input",
    "x",
  ];

  const found = [];
  for (const name of candidates) {
    const [msb, lsb] = hashHalves(name);
    const size = ex.getInputSignalSize(msb, lsb);
    // This WASM (circom 2.2.3) returns 0 for unknown hashes, not a negative
    // value, so "exists" means size > 0. (circom_runtime only treats < 0 as
    // missing, which is why probing must interpret 0 as absent.)
    const ok = size > 0;
    if (ok) found.push({ name, size });
    console.log(`${ok ? "FOUND " : "absent"}  ${name}  (size=${size})`);
  }

  console.log("");
  console.log(`Recovered ${found.length} input signals, total size ${found.reduce((a, s) => a + s.size, 0)}`);
  console.log(`Names: ${found.map((s) => s.name).join(", ")}`);
  if (found.length !== 13 || found.reduce((a, s) => a + s.size, 0) !== ex.getInputSize()) {
    console.error("MISMATCH: recovered signals do not account for the full input size.");
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
