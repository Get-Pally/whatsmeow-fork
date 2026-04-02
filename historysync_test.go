package whatsmeow

import (
	"encoding/hex"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
)

func TestBuildHistorySyncRequestUsesUnixSecondsTimestamp(t *testing.T) {
	cli := &Client{}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     types.NewJID("15551234567", types.DefaultUserServer),
			IsFromMe: true,
		},
		ID:        "wamid.oldest.123",
		Timestamp: time.Unix(1_700_000_123, 987_000_000),
	}

	msg := cli.BuildHistorySyncRequest(info, 50)
	request := msg.GetProtocolMessage().
		GetPeerDataOperationRequestMessage().
		GetHistorySyncOnDemandRequest()

	if request == nil {
		t.Fatalf("BuildHistorySyncRequest returned nil request payload")
	}
	if got := request.GetChatJID(); got != "15551234567@s.whatsapp.net" {
		t.Fatalf("unexpected chat jid: %q", got)
	}
	if got := request.GetOldestMsgID(); got != "wamid.oldest.123" {
		t.Fatalf("unexpected oldest msg id: %q", got)
	}
	if got := request.GetOnDemandMsgCount(); got != 50 {
		t.Fatalf("unexpected on-demand count: %d", got)
	}
	if got := request.GetOldestMsgTimestampMS(); got != info.Timestamp.Unix() {
		t.Fatalf("unexpected oldest message timestamp: got %d want %d", got, info.Timestamp.Unix())
	}
}

func TestBuildHistorySyncRequestDeterministicEncoding(t *testing.T) {
	cli := &Client{}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     types.NewJID("120363300129565290", types.GroupServer),
			Sender:   types.NewJID("114422810976373", types.DefaultUserServer),
			IsFromMe: false,
			IsGroup:  true,
		},
		ID:        "3a9fc03a0dde6eabeec1",
		Timestamp: time.Unix(1_774_835_921, 0),
	}

	msg := cli.BuildHistorySyncRequest(info, 50)
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal history sync request: %v", err)
	}

	expectedHex := "6242101082013d080322390a1731323033363333303031323935363532393040672e7573121433613966633033613064646536656162656563311800203228d1b1a7ce06"
	if got := hex.EncodeToString(data); got != expectedHex {
		t.Fatalf("unexpected history sync request encoding:\n got  %s\n want %s", got, expectedHex)
	}
}
