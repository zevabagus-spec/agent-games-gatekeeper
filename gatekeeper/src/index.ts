// Entrypoint: configuration from the environment, then serve.
//
// Required:
//   AGENT_GAMES_HMAC_SECRET  HMAC secret issued at registration (never
//                             committed; see .env.example). The server
//                             refuses to start without it.
//
// Optional:
//   PORT                default 3000
//   HOST                default 0.0.0.0
//   SEEN_STORE_PATH     default <project>/data/seen.json
//   CIRCUIT_WASM_PATH   default <project>/../circuits/gatekeeper.wasm
//   CIRCUIT_ZKEY_PATH   default <project>/../circuits/gatekeeper_final.zkey
//   SOFT_BUDGET_MS      default 55000 (platform deadline is 60s)
//   MAX_BODY_BYTES      default 1048576

import { resolve } from "node:path";
import { createGatekeeperServer } from "./server.js";
import { SeenStore } from "./store.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function main(): void {
  const secret = requireEnv("AGENT_GAMES_HMAC_SECRET");
  const port = Number(process.env.PORT ?? "3000");
  const host = process.env.HOST ?? "0.0.0.0";
  const projectRoot = resolve(__dirname, "..");
  const storePath =
    process.env.SEEN_STORE_PATH ?? resolve(projectRoot, "data", "seen.json");
  const wasmPath =
    process.env.CIRCUIT_WASM_PATH ?? resolve(projectRoot, "..", "circuits", "gatekeeper.wasm");
  const zkeyPath =
    process.env.CIRCUIT_ZKEY_PATH ?? resolve(projectRoot, "..", "circuits", "gatekeeper_final.zkey");
  const softBudgetMs = Number(process.env.SOFT_BUDGET_MS ?? "55000");
  const maxBodyBytes = Number(process.env.MAX_BODY_BYTES ?? "1048576");

  const server = createGatekeeperServer({
    hmacSecret: Buffer.from(secret, "utf8"),
    wasmPath,
    zkeyPath,
    store: new SeenStore(storePath),
    softBudgetMs,
    maxBodyBytes,
  });

  server.listen(port, host, () => {
    const address = server.address();
    const boundPort = typeof address === "object" && address !== null ? address.port : port;
    console.log(
      JSON.stringify({
        ts: new Date().toISOString(),
        event: "listening",
        host,
        port: boundPort,
        store: storePath,
      })
    );
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main();
