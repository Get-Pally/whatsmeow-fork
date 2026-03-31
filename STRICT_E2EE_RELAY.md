# Strict E2EE Relay Mode

This fork is the transport-only WhatsApp session used by Pally's strict E2EE relay stack.

The ownership split is intentional and non-negotiable:

- `pally-app` owns all Signal private keys, sender keys, message plaintext, history sync plaintext, and on-device decryption.
- `pally-backend-go` owns the WhatsApp websocket session, durable ciphertext queues, retry routing, transport-event extraction, and encrypted push fanout.
- This fork owns the WhatsApp transport behavior needed to support that split without falling back to server-side plaintext handling.

## Relay Mode Contract

Relay mode is enabled with `Client.SetRelayTransportMode(true)`. Once enabled, the client must behave as transport-only infrastructure.

`client.go` enforces the following in `validateRelayTransportConfiguration()`:

- `Store.TransportOnly` must be `true`.
- `Store.IdentityKey.Priv` must be `nil`.
- `Store.SignedPreKey.Priv` must be `nil`.
- Initial pairing requires:
  - public identity key
  - public signed pre-key plus signature
  - a 32-byte `AdvSecretKey`
  - `RelayPairSuccessCallback`
- A linked relay session requires:
  - `RelayMessageCallback`
  - `RelaySkdmCallback`
  - `RelayNotificationCallback`
  - `RelayRetryReceiptCallback`

If any of those invariants fail, treat it as a wiring bug in the embedding backend, not something to patch around inside the library.

## End-to-End Data Flow

### 1. Linking and Pairing

Relevant files:

- `client.go`
- `pair.go`
- `qrchan.go`

Flow:

1. The backend hydrates the device store with public bootstrap material only.
2. QR generation proceeds with an externally-owned identity and signed pre-key.
3. WhatsApp sends sign and pair-success challenges.
4. `handleRelayPair()` in `pair.go` validates the incoming pair-success payload before the external callback runs:
   - verifies the HMAC using `Store.AdvSecretKey`
   - parses the signed device identity
   - verifies the account signature against the public identity key
5. `RelayPairSuccessCallback` asks the app to build the final `account` and `device_identity` payloads.
6. `validateRelayPairSuccessResponse()` re-validates the callback result server-side before persisting anything.
7. Only after that validation passes does the store save `ID`, `LID`, platform info, and the signed account blob.

Important consequence: the app is allowed to author the pair-success response, but this fork still proves that the response matches the original WhatsApp challenge payload. The backend never blindly trusts callback output.

### 2. Inbound Encrypted Messages

Relevant files:

- `message.go`
- `relay.go`
- `client.go`

Flow:

1. The backend's relay wrapper installs `RelayMessageCallback`.
2. Encrypted `<enc>` nodes are intercepted before local Signal decryption.
3. The callback is expected to persist the ciphertext and metadata externally.
4. In relay mode, if the callback does not handle the message, local decrypt fallback is not allowed.
5. Once the embedding backend has durably queued the ciphertext, it may send the WhatsApp transport receipt.

This is the core guarantee of strict E2EE: relay mode must not quietly decrypt messages on the server because a callback was missing or declined to handle a stanza.

### 3. Sender Key Distribution Messages

Relevant files:

- `message.go`
- `client.go`

For group traffic, sender key distribution messages are forwarded to `RelaySkdmCallback` instead of being processed into the server's local sender-key store. The app must store and use them for later `skmsg` decryption.

### 4. Transport Notifications

Relevant files:

- `notification.go`

`RelayNotificationCallback` runs before normal notification handling. In relay mode:

- if the callback handles the notification, the library acks it and stops
- if the callback declines the notification, local fallback is refused

`allowRelayTransportNotificationFallback()` currently returns `false`, which is correct for strict E2EE. Transport notifications must be converted into backend-owned bridge events, not consumed locally by the backend.

### 5. Retry Receipts

Relevant files:

- `retry.go`

When a recipient cannot decrypt a message we sent, WhatsApp emits a retry receipt. In relay mode:

- `handleRetryReceipt()` forwards the request to `RelayRetryReceiptCallback`
- the library does not rebuild plaintext locally
- the external client must reconstruct the original plaintext, re-encrypt it, and resend it

If you ever see the backend rebuilding plaintext in relay mode, that is a design regression.

### 6. Outbound Sends

Relevant files:

- `send.go`

`Client.SendMessage()` returns `ErrRelayTransportRequiresPreEncryptedSend` in relay mode.

That is deliberate. In strict E2EE:

- the app encrypts outbound messages
- the backend sends raw encrypted WhatsApp nodes
- this fork must not accept plaintext outbound messages from the backend

### 7. History Sync

Relevant files:

- `message.go`
- `errors.go`

History sync is delegated to the external client:

- `handleHistorySyncNotificationLoop()` exits immediately in relay mode
- `DownloadHistorySync()` returns `ErrRelayTransportOwnsHistory`

The app decrypts history sync notifications and blobs locally. The server must not download and decrypt them.

## Source Map

- `client.go`: relay-mode flags and configuration validation
- `pair.go`: pair-success validation and external callback handoff
- `message.go`: message interception, SKDM forwarding, history-sync disablement
- `notification.go`: notification interception and no-fallback enforcement
- `retry.go`: retry-receipt forwarding
- `send.go`: plaintext send rejection in relay mode
- `relay_transport_test.go`: relay transport invariant coverage
- `pair_relay_test.go`: pair-success validation coverage

## Non-Negotiable Rules

- Never store Signal private identity or signed pre-key material in the relay device store.
- Never add a local decrypt fallback path in relay mode.
- Never re-enable plaintext `SendMessage()` for relay sessions.
- Never process history sync, app-state secrets, or privacy-token state locally just to make another layer simpler.
- Never trust externally supplied pair-success blobs without re-validating them against the original WhatsApp payload.
- When the bridge contract changes, update the backend proto and app client first; do not add compatibility branches inside this fork.

## Debugging

### Fast Failure Checklist

- QR/linking fails immediately:
  - check `validateRelayTransportConfiguration()`
  - confirm `Store.TransportOnly == true`
  - confirm both private keys are `nil`
  - confirm the pairing `AdvSecretKey` is exactly 32 bytes
- Pairing fails after scan:
  - look for `hmac-mismatch`
  - look for `signature-mismatch`
  - inspect the app-generated pair-success payload and the backend callback wiring
- Messages reach the backend but not the app:
  - verify `RelayMessageCallback` is installed
  - verify the callback returns handled success only after durable queue write
- Group decrypts fail on the app:
  - verify `RelaySkdmCallback` is installed
  - confirm SKDMs are forwarded instead of being consumed locally
- Retries do nothing:
  - verify `RelayRetryReceiptCallback` is installed
  - confirm the backend caches the original raw node long enough for retry receipt requests

### Useful Error Strings

- `ErrRelayTransportRequiresTransportOnlyStore`
- `ErrRelayTransportRequiresPairSuccessCallback`
- `ErrRelayTransportRequiresMessageCallback`
- `ErrRelayTransportRequiresSKDMCallback`
- `ErrRelayTransportRequiresNotificationCallback`
- `ErrRelayTransportRequiresRetryCallback`
- `ErrRelayTransportRequiresPreEncryptedSend`
- `ErrRelayTransportOwnsHistory`

### Verification

Run:

```bash
go test ./...
```

The relay-mode tests in this fork are the first place to add coverage when changing a relay callback contract or pairing invariant.
