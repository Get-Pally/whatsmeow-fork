# AI_CONTEXT.md

This file provides guidance to AI coding agents working in this repository.
`AGENTS.md` and `CLAUDE.md` both point here.

## Workspace Rules

- This relay stack is not deployed yet. Prefer clean end-to-end fixes over compatibility fallbacks.
- Finish the end-to-end debugging loop before stopping when feasible: patch the most likely canonical cause, verify it, and re-check the resulting logs instead of stopping at an intermediate diagnosis.
- Do not add heuristics, temporary patches, or backward-compatibility branches to preserve old relay data or contracts.
- If a field belongs in the canonical backend or protobuf contract, thread it through correctly instead of inferring it on the client.
- When the canonical schema changes, update the source schema and regenerate derived files instead of hand-maintaining divergent generated code.

## Repo Role

This repository is the forked `whatsmeow` transport layer used by Pally's strict E2EE relay stack.

- This repo owns transport-only WhatsApp session behavior.
- `pally-backend-go` owns bridge APIs, durable ciphertext queues, and relay orchestration.
- `pally-app` owns Signal private keys, plaintext, history sync decryption, and outbound encryption.

## Relay-Specific Guidance

- Relay mode must stay transport-only.
- Do not add server-side plaintext send or decrypt fallbacks in relay mode.
- Do not persist Signal private identity or signed pre-key material in the relay device store.
- Pair-success responses from the app must always be re-validated against the original WhatsApp payload before persistence.
- History sync belongs to the app in relay mode; this fork must continue rejecting local history-sync download/processing there.

## Debugging Workflow

- Start with the live app logs first: `~/Library/Logs/PallyApp/<latest>/`, then correlate with `/tmp/pally-server.log` and `/tmp/pally-backend.log` by exact timestamp, message ID, and JID. Old container log paths are secondary.
- For send failures, trace in this order: app target resolution/encryption mode -> backend outbound node/fanout -> WhatsApp ack/receipt/retry. Check upstream `send.go` before changing relay behavior; most real bugs were contract drift, not missing fallbacks.
- For linking failures, separate QR generation from stale bridge events. Verify whether the app actually received a QR, whether `pair-success` validation failed, and whether stale `link_*` events leaked across attempts before changing the transport flow.
- For history scrollback, trace in this order: app `[BACKFILL_*]` logs -> backend `category="peer"` send + server ack -> returned peer/history message. If the app sends the correct bare self JID and WhatsApp acks the request but no history response comes back, do not keep changing bridge polling/import logic.
- When history sync looks wrong, compare the app request bytes against upstream `BuildHistorySyncRequest`, not just decoded fields. Use deterministic fixtures/tests before changing runtime code.
- Prefer canonical contract fixes across repos. If a field belongs in protobuf, bridge JSON, or the transport event schema, thread it through cleanly instead of inferring it on the client.
- Add narrow runtime logs that summarize payloads with IDs, counts, timestamps, and digests. Do not dump plaintext or large blobs into logs.

## Detailed Docs

- Relay transport contract, data flow, invariants, and debugging:
  - `STRICT_E2EE_RELAY.md`
- General repo overview:
  - `README.md`

## Verification

Use:

```bash
go test ./...
```
