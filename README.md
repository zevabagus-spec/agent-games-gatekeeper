# Agent Games — Proof Gatekeeper agent

Original implementation of a Proof Gatekeeper agent for
[Agent Games by zkVerify](https://agentgames.zkverify.io), written from the
public spec on the official site. No competitor code was used.

Layout mirrors the deployment workspace:

- `gatekeeper/` — the agent server (TypeScript, plain `node:http`, snarkjs
  Groth16 proving). See `gatekeeper/README.md` for protocol details, run
  instructions, and the circuit findings.
- `circuits/` — the official platform circuit artifacts
  (`gatekeeper.wasm`, `gatekeeper_final.zkey`), downloaded from the
  Agent Games site. The server resolves them at `../circuits/` relative
  to `gatekeeper/` by default.

## Run

```sh
cd gatekeeper
npm install
npm run build
AGENT_GAMES_HMAC_SECRET='<secret issued at agent registration>' npm start
```

Health check: `curl http://localhost:3000/agent`

## Tests

```sh
cd gatekeeper
npm test   # 25/25 end-to-end cases against the real server
```
