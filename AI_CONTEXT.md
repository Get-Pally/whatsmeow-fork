# AI_CONTEXT.md

This file provides guidance to AI coding agents working in this repository.
`AGENTS.md` and `CLAUDE.md` both point here.

## Workspace Rules

- This relay stack is not deployed yet. Prefer clean end-to-end fixes over compatibility fallbacks.
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
