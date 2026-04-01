# Relay Initial Sync and Backfill Plan

## Goal

Make relay startup, history bootstrap, and later conversation backfill safe and restartable while keeping the current transport-only contract:

- the backend stores, orders, and forwards encrypted WhatsApp envelopes
- the app owns Signal state, decryption, history parsing, and database import
- the backend never decrypts message payloads

This plan is based on the current live relay logs plus the current code paths in:

- `pally-app/seoul/Pally/Services/Messaging/WhatsApp/RelayWhatsAppService.swift`
- `pally-app/seoul/Pally/Services/Messaging/WhatsAppRelay/Core/WhatsAppE2EEManager.swift`
- `pally-app/seoul/Pally/Services/Messaging/WhatsAppRelay/Core/WhatsAppRelaySession+E2EE.swift`
- `pally-backend-go/gwangju/internal/whatsapp/bridge_handlers.go`
- `pally-backend-go/gwangju/internal/whatsapp/store.go`

## Implementation Update

After re-checking the backend queue semantics in `store.go`, the app does **not** need a second durable inbox table for correctness.

Why:

- the backend retains envelopes until `client_processed_at` is set
- `delivered_to_client_at` is only telemetry; it does not remove rows from replay
- if the app crashes after fetch, delivery ack, decrypt, or partial import, the backend will replay the envelope on the next poll until the app sends the process result

That means the mandatory correctness work is:

1. delay bridge process acks until app DB/history import commit succeeds
2. keep history/backfill imports idempotent so replay is safe
3. implement real relay-side on-demand history requests for conversation backfill
4. keep initial-sync progress tied to history bootstrap completion rather than the first sync loop

This is the implementation direction now reflected in the app code. The larger local-inbox schema described below remains an optional future optimization for local observability/offline worker separation, not a hard requirement for correctness.

## Current Observed Startup Flow

### Live startup sequence

From the current runtime logs:

- App logs:
  - `~/Library/Containers/com.pally.dev/Data/Library/Logs/PallyApp/20260330_103625_22167/WhatsAppRelay.log`
  - `~/Library/Containers/com.pally.dev/Data/Library/Logs/PallyApp/20260330_103625_22167/WhatsAppDecryption.log`
  - `~/Library/Containers/com.pally.dev/Data/Library/Logs/PallyApp/20260330_103625_22167/WhatsAppHistorySync.log`
  - `~/Library/Containers/com.pally.dev/Data/Library/Logs/PallyApp/20260330_103625_22167/all.jsonl`
- Backend logs:
  - `/tmp/pally-server.log`
  - `/tmp/pally-backend.log`

Observed sequence:

1. The app opens a bridge session with `POST /whatsapp/bridge/v1/hello`.
2. The app sends transport bootstrap queries with `POST /whatsapp/bridge/v1/query`.
3. The app starts polling with `POST /whatsapp/bridge/v1/poll`.
4. The backend queues startup transport events first, currently including `prekeys_low`.
5. The backend then begins queueing encrypted inbound WhatsApp messages.
6. The first peer messages from the primary device are `pkmsg` items from `14159366889@s.whatsapp.net`.
7. One of those peer messages contains a `HistorySyncNotification`:
   - first non-blocking chunk: `57 conversations`, `0 messages`
   - later initial chunk: `899 conversations`, `0 messages`, `progress=1%`
8. After peer history processing, group traffic begins arriving and many messages fail with `sessionNotFound(...)`.
9. Retry receipts are requested, but the backlog is not yet safe enough for full restartable import.

### Why peer messages are processed first

The current ordering is intentional and correct:

- the backend prioritizes peer messages because they can contain history sync notifications
- the app processes peer messages before the general queue because history sync and embedded SKDMs can unblock later group decrypts

This matches the current code and should stay.

## Current Message Taxonomy

### Bridge session messages

`hello`

- Establishes the bridge session and cursor baseline.
- Carries protocol version, client instance ID, device/account identifiers, and public bootstrap material.

`poll`

- Is both the fetch path and the acknowledgement path.
- Sends:
  - last inbound cursor
  - delivery acks
  - process results
  - retry request results
  - transport event results
  - SKDM results
- Returns ordered relay envelopes.

### Backend-to-app envelope kinds

`message`

- Encrypted WhatsApp message envelope.
- Contains ciphertext, raw node bytes, metadata, sender/chat JIDs, and cursor.
- May be peer or group traffic.

`transport_event`

Current startup-relevant types:

- `prekeys_low`
- `identity_change`
- `appstate_update`
- `privacy_token`
- `media_retry`
- `link_*` during pairing

`retry_request`

- A request for the client to rebuild and send retry material because the server cannot decrypt and replay on its own.

`skdm`

- Sender key distribution material needed to decrypt later group traffic.

### History sync

History sync is not served by a backend history endpoint.

It currently arrives inside decrypted peer messages as a `HistorySyncNotification`, usually with:

- inline payload for some chunks
- downloadable blob metadata for others
- sync types including `non_blocking_data`, `initial`, `recent`, and `on_demand`

This is the correct transport boundary. The server should continue to treat it as opaque encrypted traffic.

## Current Processing Paths

### Backend

Current backend behavior is structurally correct:

- Intercept encrypted WhatsApp inbound envelopes.
- Persist them in queue tables with a `bridge_cursor`.
- Apply poll acks before fetching more envelopes.
- Return ordered bridge envelopes without decrypting.

Relevant code:

- `pally-backend-go/gwangju/internal/whatsapp/bridge_handlers.go`
- `pally-backend-go/gwangju/internal/whatsapp/store.go`

Important current queue behavior:

- peer fetch is intentionally prioritized
- general bridge fetch is ordered by `bridge_cursor ASC`
- rows remain until `client_processed_at` is set

### App

Current app startup behavior in `RelayWhatsAppService.run()` is:

1. subscribe to live events
2. sync local user contact
3. `e2eeManager.processQueuedMessages()`
4. if `getHistorySyncData()` exists, call `importHistorySync(...)`
5. `persistDecryptedEvents(...)`
6. `syncContacts()`
7. `syncConversations()`
8. `sendPendingMessages()`

Current app queue behavior in `WhatsAppE2EEManager` is:

1. process pending transport events
2. process pending retry requests
3. process pending SKDMs
4. fetch peer messages first
5. fetch general queued messages
6. decrypt
7. immediately send queue results back to backend

## Main Finding: Startup Ordering Is Logical but Not Yet Durable

The current ordering is logically correct, but it is not safe for full backfill or restart-safe initial sync.

### The unsafe gap

The app currently sends bridge process acks before the imported history or decrypted messages are durably written into the app database.

Today:

- `processQueuedMessage(...)` and `processQueuedMessageForHistorySync(...)` call:
  - `markQueuedMessageDelivered(...)`
  - decrypt locally
  - `submitQueuedMessageResult(...)`
- `submitQueuedMessageResult(...)` writes the process result into pending bridge state and immediately calls `bridgePoll(maxItems: 0)`
- only later does `RelayWhatsAppService.run()` import history and persist decrypted events into the app DB

If the app dies in that window:

- the backend has already accepted the process result
- the bridge cursor may already have advanced
- the local imported history/message record may not exist
- the chunk or message can be lost from the startup path

This is the primary correctness bug to fix before doing full backfill.

## Additional Gaps

### 1. No durable local relay inbox

Incoming bridge envelopes are not yet committed into a dedicated durable local inbox before delivery/process acks are sent.

Need:

- a durable, replayable local inbox
- local import state per queue item
- crash-safe restart behavior

### 2. History sync state is in-memory only

`WhatsAppE2EEManager` currently accumulates parsed history data in memory.

That means:

- initial sync progress is not durable
- partial chunks are not durable
- restart during bootstrap can lose parsed but unimported history

### 3. Initial sync is not an explicit state machine

Startup is currently a best-effort loop, not a durable phased process.

Need explicit phases such as:

- `bridge_open`
- `transport_warmup`
- `peer_history_bootstrap`
- `history_import`
- `conversation_metadata_sync`
- `conversation_backfill`
- `steady_state`

### 4. Conversation backfill is not implemented on relay

`RelayWhatsAppService.fetchOlderMessages(...)` currently just sets `hasOlderMessages = false`.

That means there is no real relay-side implementation for:

- requesting older messages for one conversation
- tracking outstanding requests
- consuming `on_demand` history sync replies

### 5. `appstate_update` is only stored, not acted on

The app currently persists appstate collection hints but does not turn them into actual sync jobs.

That leaves:

- conversation metadata drift
- archive/mute/pin/read-state drift
- patch-driven incremental sync incomplete

### 6. Group warmup is still opportunistic

The current peer-first ordering helps, but group decrypt still fails for many conversations with `sessionNotFound(...)`.

Need:

- durable replay
- sender-key/session warmup strategy
- retry scheduling that survives restart

## Target Design

## A. Make bridge processing commit-aware on the app

- Poll returns envelopes from the durable backend queue.
- The app may mark them delivered immediately for telemetry, but must not send process results yet.
- The app decrypts/parses/imports locally.
- Only after successful app DB/history import commit should it send bridge process results.

Because the backend already replays all rows with `client_processed_at IS NULL`, this preserves the server-opaque model and remains restart-safe without duplicating the queue locally.

## B. Keep delivery acknowledgement separate from processing acknowledgement

Current meaning is too eager.

Implemented rule:

- `delivered_to_client` means "observed by the client"
- `client_processed_at` means "fully applied into the app state machine and/or app database"

This lets the backend remain the durable relay while still giving correct handoff semantics.

## C. Treat history sync as a commit-gated import, not a side effect

History sync processing should become:

1. decrypt and parse the history notification on-device
2. import the resulting conversations/messages idempotently into the app DB
3. only then ack the source queue item as processed

The current implementation uses backend replay plus idempotent import instead of a separate client-side chunk journal.

## D. Make initial sync explicit and resumable

Initial sync should become a durable state machine with checkpoints stored locally.

Required properties:

- restart-safe
- idempotent
- can resume mid-chunk and mid-conversation
- can distinguish "history metadata imported" from "conversation backlog complete"

## Concrete Schema Changes

## App-side schema additions

These are no longer mandatory for correctness after the backend replay re-check. They remain optional future work if we want a fully decoupled local relay worker and richer local inspection/debugging.

### 1. `wa_relay_inbox`

Purpose:

- durable landing zone for every bridge envelope

Suggested columns:

- `queue_id TEXT PRIMARY KEY`
- `bridge_session_id TEXT NOT NULL`
- `bridge_cursor INTEGER NOT NULL`
- `envelope_type TEXT NOT NULL`
- `message_id TEXT`
- `chat_jid TEXT`
- `sender_jid TEXT`
- `is_group INTEGER`
- `payload_json BLOB`
- `encrypted_payload BLOB`
- `raw_node BLOB`
- `received_at_ms INTEGER NOT NULL`
- `delivery_acked_at_ms INTEGER`
- `processing_started_at_ms INTEGER`
- `processed_at_ms INTEGER`
- `process_result TEXT`
- `process_error_code TEXT`
- `process_error_description TEXT`
- `source_timestamp_ms INTEGER`

Indexes:

- `(processed_at_ms, bridge_cursor)`
- `(chat_jid, source_timestamp_ms)`
- `(message_id)`

### 2. `wa_history_sync_chunk`

Purpose:

- durable storage for parsed history sync chunks before import

Suggested columns:

- `chunk_id TEXT PRIMARY KEY`
- `source_queue_id TEXT NOT NULL`
- `sync_type TEXT NOT NULL`
- `progress INTEGER NOT NULL`
- `chunk_order INTEGER`
- `original_message_id TEXT`
- `peer_data_request_session_id TEXT`
- `direct_path TEXT`
- `blob_sha256 TEXT`
- `inline_payload BLOB`
- `downloaded_blob BLOB`
- `parse_state TEXT NOT NULL`
- `import_state TEXT NOT NULL`
- `conversation_count INTEGER NOT NULL`
- `message_count INTEGER NOT NULL`
- `created_at_ms INTEGER NOT NULL`
- `updated_at_ms INTEGER NOT NULL`

Indexes:

- `(import_state, sync_type, chunk_order)`
- `(source_queue_id)`
- `(peer_data_request_session_id)`

### 3. `wa_history_sync_conversation`

Purpose:

- normalized durable chunk contents before final DB import

Suggested columns:

- `chunk_id TEXT NOT NULL`
- `conversation_jid TEXT NOT NULL`
- `name TEXT`
- `message_count INTEGER NOT NULL`
- `latest_message_ts_ms INTEGER`
- `payload_json BLOB NOT NULL`
- primary key `(chunk_id, conversation_jid)`

### 4. `wa_initial_sync_state`

Purpose:

- durable state machine checkpointing

Suggested columns:

- `singleton_key TEXT PRIMARY KEY`
- `phase TEXT NOT NULL`
- `bridge_session_id TEXT`
- `last_inbox_cursor INTEGER NOT NULL`
- `last_delivery_acked_cursor INTEGER NOT NULL`
- `last_process_acked_cursor INTEGER NOT NULL`
- `history_bootstrap_progress INTEGER NOT NULL`
- `conversation_metadata_import_complete INTEGER NOT NULL`
- `full_backfill_started INTEGER NOT NULL`
- `full_backfill_completed INTEGER NOT NULL`
- `last_error TEXT`
- `updated_at_ms INTEGER NOT NULL`

### 5. `wa_backfill_request`

Purpose:

- durable per-conversation backfill jobs

Suggested columns:

- `request_id TEXT PRIMARY KEY`
- `conversation_id TEXT NOT NULL`
- `chat_jid TEXT NOT NULL`
- `state TEXT NOT NULL`
- `oldest_known_message_id TEXT`
- `oldest_known_timestamp_ms INTEGER`
- `oldest_known_sender_jid TEXT`
- `requested_count INTEGER NOT NULL`
- `request_message_id TEXT`
- `peer_data_request_session_id TEXT`
- `expected_sync_type TEXT`
- `created_at_ms INTEGER NOT NULL`
- `updated_at_ms INTEGER NOT NULL`
- `last_error TEXT`

Indexes:

- `(conversation_id, state)`
- `(chat_jid, state)`

### 6. `wa_transport_hint`

Purpose:

- durable appstate/media/privacy work queue

Suggested columns:

- `id TEXT PRIMARY KEY`
- `hint_type TEXT NOT NULL`
- `scope_key TEXT`
- `payload_json BLOB NOT NULL`
- `state TEXT NOT NULL`
- `created_at_ms INTEGER NOT NULL`
- `updated_at_ms INTEGER NOT NULL`

## Backend-side schema changes

Mandatory backend schema changes should stay minimal.

The backend already durably stores inbound encrypted envelopes and transport queues correctly enough for the relay model.

Recommended backend additions:

### 1. Optional `client_delivery_state` telemetry fields

Purpose:

- improve debugging for stalled initial sync

Possible additions:

- `delivery_ack_count`
- `process_ack_count`
- `last_client_seen_at`

This is operationally useful but not required for correctness.

### 2. Optional queue visibility metrics

Purpose:

- inspect backlog shape without touching ciphertext

Possible materialized views or queries:

- outstanding message queue rows by `client_processed_at IS NULL`
- outstanding SKDM rows by user
- outstanding retry requests by user

No backend decryption changes are required.

## Required Code Changes

## 1. App: durable inbox ingest before any ack

Files to change:

- `pally-app/seoul/Pally/Services/Messaging/WhatsAppRelay/Core/WhatsAppRelaySession+E2EE.swift`
- `pally-app/seoul/Pally/Services/Messaging/WhatsAppRelay/Core/WhatsAppE2EEManager.swift`
- `pally-app/seoul/Pally/Services/Messaging/WhatsApp/RelayWhatsAppService.swift`

Changes:

- When `bridgePoll` returns envelopes, write them into `wa_relay_inbox` in a transaction.
- Persist the newest durable inbox cursor only after that transaction commits.
- Do not immediately keep bridge state only in memory or keychain.
- `markQueuedMessageDelivered(...)` should run only after local inbox commit.
- `markQueuedMessageProcessed(...)` should run only after message/history import commit.

## 2. App: convert queue processing into inbox worker

Replace "decrypt directly from bridge response" with:

- `ingest bridge envelopes -> inbox rows`
- `inbox worker -> decrypt/process`
- `app DB import -> mark inbox row imported`
- `send process ack`

Worker ordering should be:

1. transport hints
2. retry requests
3. SKDM
4. peer messages
5. general messages

That ordering is already good and should stay.

## 3. App: make history sync durable and resumable

Files to change:

- `pally-app/seoul/Pally/Services/Messaging/WhatsAppRelay/Core/WhatsAppE2EEManager.swift`
- `pally-app/seoul/Pally/Services/Messaging/WhatsApp/RelayWhatsAppService.swift`
- adapter/database layer files that own conversation/message insertion

Changes:

- Persist each history chunk before import.
- Split parsing from importing.
- Track per-chunk import state.
- Make `clearHistorySyncData()` a final cleanup step only after successful import.
- On startup, resume unfinished history chunk imports before fetching new backlog.

## 4. App: implement real `fetchOlderMessages(...)`

Current stub must be replaced.

Required behavior:

1. Resolve the oldest known remote WhatsApp message anchor for the conversation.
2. Create a durable `wa_backfill_request`.
3. Build a real on-demand history request from that anchor.
4. Send the request through the existing relay raw-node send path.
5. Wait for `HistorySyncNotification(sync_type=on_demand)`.
6. Correlate the response to the open request using request metadata.
7. Import the results.
8. Update `hasOlderMessages` based on actual imported result, not a stub.

If the current app cannot build the required history request payload locally, add a small typed helper on the relay session layer that constructs the raw WhatsApp node from local inputs and forwards it unchanged through the backend.

## 5. App: turn `appstate_update` into real work

Current behavior is only:

- store appstate collection hints

Needed behavior:

- schedule collection sync jobs
- process patch collections in a durable worker
- update read/archive/mute/pin/disappearing/message settings in app DB
- ensure these jobs are restart-safe

## 6. App: improve group warmup and retry semantics

Current logs show repeated `sessionNotFound(...)` after initial history bootstrap.

Needed:

- retry jobs should be durable, not best-effort side effects
- a failed group decrypt should stay in inbox state `waiting_for_keys` instead of terminal failure
- new SKDMs or retry responses should re-queue dependent messages

Recommended inbox process states:

- `queued`
- `waiting_for_transport`
- `waiting_for_skdm`
- `waiting_for_session`
- `ready_to_decrypt`
- `importing`
- `processed`
- `failed_terminal`

## 7. Backend: keep bridge semantics, add only support surfaces

Backend changes should remain narrow:

- keep bridge opaque
- keep cursor ordering
- keep applying acks before fetch

Needed backend support:

- ensure raw-node outbound path can carry history sync requests from app
- ensure retry/SKDM/event queues continue to participate in the same cursor stream
- add diagnostics for bridge session lag and envelope backlog

No backend history import endpoint should be reintroduced.

## Initial Sync State Machine

The app should persist and publish a durable phased state machine:

### Phase 0: `bridge_open`

- `hello` succeeded
- bridge session established
- local relay inbox available

Exit criteria:

- transport bootstrap queries complete

### Phase 1: `transport_warmup`

- process `prekeys_low`, `identity_change`, `privacy_token`, `media_retry`, `appstate_update`
- process queued SKDMs and retry requests

Exit criteria:

- no blocking transport prerequisites remain

### Phase 2: `peer_history_bootstrap`

- ingest peer messages first
- detect and persist history sync notifications
- parse chunks
- extract SKDM material from history chunks

Exit criteria:

- initial peer bootstrap chunk set imported or no more peer history remains

### Phase 3: `message_import`

- import decrypted regular messages
- import conversation metadata updates
- record latest remote anchors per conversation

Exit criteria:

- current startup inbox drained to zero or all remaining rows are waiting on keys

### Phase 4: `conversation_metadata_sync`

- run contacts/conversation reconciliation
- consume appstate patch hints

Exit criteria:

- conversation metadata consistent enough for UI presentation

### Phase 5: `conversation_backfill`

- create per-conversation backfill jobs
- request older messages only for conversations that need them
- import `on_demand` history chunks

Exit criteria:

- user-visible conversations have reached configured local history target

### Phase 6: `steady_state`

- continue regular relay polling
- process live traffic
- service backfill jobs opportunistically

## Backfill Strategy

Full backfill should not mean "request everything immediately".

Recommended policy:

### Tier 1: startup bootstrap

- import initial history sync chunks
- create conversations and recent metadata
- warm up sender keys and sessions

### Tier 2: visible conversations

- backfill conversations shown in the inbox first
- then active/favorited/pinned conversations

### Tier 3: lazy historical expansion

- request older history only when:
  - the user opens a conversation
  - the user scrolls near the top
  - a configured background budget allows it

This keeps first-run cost bounded while still allowing full eventual backfill.

## Ack and Cursor Rules

These rules are required for correctness:

### Delivery ack

Send only after:

- envelope is durably written to `wa_relay_inbox`

Do not send only because the envelope was decoded in memory.

### Process ack

Send only after:

- decrypted message import transaction committed, or
- history sync chunk import transaction committed, or
- durable terminal failure state recorded

### Cursor advancement

Persist distinct local checkpoints:

- highest cursor fetched from backend
- highest cursor durably inboxed
- highest cursor delivery-acked
- highest cursor fully processed

Do not collapse these into one value.

## Observability

Keep and standardize these markers during implementation:

Backend:

- `[MSG_INTERCEPT]`
- `[TRANSPORT_EVENT]`
- `[WM_HISTORY_SYNC]`
- `[RELAY_NOTIFICATION]`
- add `[BRIDGE_ENVELOPE_WRITE]`
- add `[BRIDGE_CURSOR_ADVANCE]`

App bridge/API:

- `[API_PROTO_REQ]`
- `[API_PROTO_RESP]`
- add `[BRIDGE_INBOX_WRITE]`
- add `[BRIDGE_INBOX_RESUME]`

App queue/history:

- `[E2EE_QUEUE_*]`
- `[HISTORY_*]`
- `[ADAPTER_HISTORY_*]`
- add `[BACKFILL_REQUEST]`
- add `[BACKFILL_RESULT]`
- add `[SYNC_PHASE]`

These logs should make it obvious where a startup is stuck:

- bridge fetch
- inbox ingest
- history parse
- DB import
- process ack
- conversation backfill

## Implementation Order

## Phase 1: correctness first

1. Add `wa_relay_inbox`.
2. Ingest all bridge envelopes into it before any acks.
3. Delay process acks until DB/history import commit.
4. Add durable sync checkpoints.

This is the minimum needed to make startup restart-safe.

## Phase 2: durable history bootstrap

1. Add `wa_history_sync_chunk` and `wa_history_sync_conversation`.
2. Persist parsed chunks and import state.
3. Resume unfinished history imports on startup.

## Phase 3: explicit initial sync state machine

1. Add `wa_initial_sync_state`.
2. Publish sync phase and progress.
3. Make the startup loop idempotent.

## Phase 4: real conversation backfill

1. Replace the stub `fetchOlderMessages(...)`.
2. Add `wa_backfill_request`.
3. Correlate `on_demand` history sync responses and import them.

## Phase 5: appstate-driven reconciliation

1. Add durable `wa_transport_hint`.
2. Turn `appstate_update` into actual sync jobs.
3. Reconcile archive/mute/pin/read state and other patch-driven metadata.

## Phase 6: operational hardening

1. Add bridge lag metrics and queue depth visibility.
2. Add replay tests for crash/restart mid-import.
3. Add long-run soak tests with large history sets and group-heavy accounts.

## Test Matrix

### App crash windows

Test all of these:

- crash after poll response, before inbox commit
- crash after inbox commit, before delivery ack
- crash after delivery ack, before decrypt
- crash after decrypt, before history/message DB import
- crash after DB import, before process ack
- crash after process ack, before cursor checkpoint update

Expected result:

- no lost history chunks
- no lost decrypted messages
- idempotent replay on restart

### History sync shapes

- inline non-blocking chunk
- downloaded initial chunk
- on-demand chunk
- multiple chunks out of order
- duplicate chunk replay

### Group warmup

- SKDM arrives before ciphertext
- ciphertext arrives before SKDM
- retry request succeeds after initial `sessionNotFound`
- multiple group participants missing sessions

### Backfill

- open conversation with existing anchor
- anchor missing
- repeated backfill request dedupe
- partial import then restart

### Appstate

- archive/unarchive
- mark read/unread
- mute/pin/disappearing mode updates
- patch hints received during initial sync

## Recommended Non-Goals

Do not do these:

- reintroduce server-side decryption
- add a server-side history import endpoint
- make the backend own app-level conversation state

The right fix is better client durability and a clearer relay state machine.

## Bottom Line

The current relay startup path is logically correct in ordering:

- `hello` and `poll` are working
- peer messages are prioritized correctly
- history sync is arriving on the right channel
- the backend is staying within the transport-only boundary

But it is not yet safe for full backfill because the app acknowledges processing before durable app import.

The first milestone is therefore not "more history features". It is:

- durable local relay inbox
- commit-aware acking
- durable history sync journal
- resumable initial sync state machine

Once those are in place, conversation-scoped on-demand backfill and appstate-driven reconciliation can be layered on without breaking the transport-only model.
