package whatsmeow

import (
	"testing"
	"time"

	waE2E "go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
)

func TestPeerMessageAttrsMarksHistorySyncOnDemandRequestsPrivacySensitive(t *testing.T) {
	cli := &Client{}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     types.NewJID("15551234567", types.DefaultUserServer),
			IsFromMe: true,
		},
		ID:        "wamid.oldest.123",
		Timestamp: time.Unix(1_700_000_123, 0),
	}

	attrs := peerMessageAttrs(types.NewJID("15551234567", types.DefaultUserServer), types.MessageID("peer-request-id"), cli.BuildHistorySyncRequest(info, 50))

	if got := attrs["privacy_sensitive"]; got != "1" {
		t.Fatalf("expected history sync request to be marked privacy-sensitive, got %v", got)
	}
	if _, ok := attrs["push_priority"]; ok {
		t.Fatalf("did not expect history sync request to set push_priority")
	}
}

func TestPeerMessageAttrsMarksHistorySyncChunkRetryPrivacySensitive(t *testing.T) {
	attrs := peerMessageAttrs(types.NewJID("15551234567", types.DefaultUserServer), types.MessageID("chunk-retry-id"), &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
			PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
				PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_HISTORY_SYNC_CHUNK_RETRY.Enum(),
			},
		},
	})

	if got := attrs["privacy_sensitive"]; got != "1" {
		t.Fatalf("expected chunk retry request to be marked privacy-sensitive, got %v", got)
	}
	if _, ok := attrs["push_priority"]; ok {
		t.Fatalf("did not expect chunk retry request to set push_priority")
	}
}

func TestPeerMessageAttrsKeepsAppStateRequestsHighPriority(t *testing.T) {
	attrs := peerMessageAttrs(types.NewJID("15551234567", types.DefaultUserServer), types.MessageID("app-state-request-id"), &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST.Enum(),
		},
	})

	if got := attrs["push_priority"]; got != "high" {
		t.Fatalf("expected app state sync request to be high priority, got %v", got)
	}
	if _, ok := attrs["privacy_sensitive"]; ok {
		t.Fatalf("did not expect app state sync request to be marked privacy-sensitive")
	}
}
