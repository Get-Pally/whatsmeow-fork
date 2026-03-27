package whatsmeow

import (
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

func TestBuildRelayMessageNodeIncludesParticipantsAndDeviceIdentity(t *testing.T) {
	cli := &Client{
		Store: &store.Device{
			Account: &waAdv.ADVSignedDeviceIdentity{
				Details: []byte("device-details"),
			},
		},
	}

	to := types.NewJID("15551234567", types.DefaultUserServer)
	node, err := cli.buildRelayMessageNode(
		to,
		[]RelayParticipantMessage{{
			JID:            types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer},
			EncryptionType: RelayEncryptionPreKey,
			Payload:        []byte("ciphertext"),
			MediaType:      "image",
		}},
		RelayMessageOptions{},
		"relay-msg-1",
		"media",
	)
	if err != nil {
		t.Fatalf("buildRelayMessageNode returned error: %v", err)
	}

	if got := node.Tag; got != "message" {
		t.Fatalf("unexpected node tag: %s", got)
	}
	if got := node.Attrs["id"]; got != types.MessageID("relay-msg-1") {
		t.Fatalf("unexpected message id attr: %#v", got)
	}
	if got := node.Attrs["type"]; got != "media" {
		t.Fatalf("unexpected message type attr: %#v", got)
	}
	if got := node.Attrs["to"]; got != to {
		t.Fatalf("unexpected to attr: %#v", got)
	}

	content, ok := node.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("unexpected node content type: %T", node.Content)
	}
	if len(content) != 2 {
		t.Fatalf("expected participants + device identity, got %d children", len(content))
	}
	if content[0].Tag != "participants" {
		t.Fatalf("expected first child to be participants, got %s", content[0].Tag)
	}
	if content[1].Tag != "device-identity" {
		t.Fatalf("expected second child to be device-identity, got %s", content[1].Tag)
	}

	participants, ok := content[0].Content.([]waBinary.Node)
	if !ok || len(participants) != 1 {
		t.Fatalf("unexpected participants content: %T len=%d", content[0].Content, len(participants))
	}
	if participants[0].Tag != "to" {
		t.Fatalf("expected participant child to be to, got %s", participants[0].Tag)
	}
	if got := participants[0].Attrs["jid"]; got != (types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer}) {
		t.Fatalf("unexpected participant jid attr: %#v", got)
	}

	encChildren, ok := participants[0].Content.([]waBinary.Node)
	if !ok || len(encChildren) != 1 {
		t.Fatalf("unexpected participant enc content: %T len=%d", participants[0].Content, len(encChildren))
	}
	if encChildren[0].Tag != "enc" {
		t.Fatalf("expected enc child, got %s", encChildren[0].Tag)
	}
	if got := encChildren[0].Attrs["type"]; got != string(RelayEncryptionPreKey) {
		t.Fatalf("unexpected enc type: %#v", got)
	}
	if got := encChildren[0].Attrs["mediatype"]; got != "image" {
		t.Fatalf("unexpected mediatype attr: %#v", got)
	}
	if got := string(encChildren[0].Content.([]byte)); got != "ciphertext" {
		t.Fatalf("unexpected ciphertext payload: %q", got)
	}
}

func TestBuildRelayGroupMessageNodeIncludesFanoutAndSenderKey(t *testing.T) {
	cli := &Client{}
	groupJID := types.NewJID("1234567890", types.GroupServer)
	participant := RelayParticipantMessage{
		JID:            types.JID{User: "15551234567", Device: 9, Server: types.DefaultUserServer},
		EncryptionType: RelayEncryptionNormal,
		Payload:        []byte("skdm"),
	}

	node, err := cli.buildRelayGroupMessageNode(
		groupJID,
		[]RelayParticipantMessage{participant},
		[]byte("sender-key-ciphertext"),
		RelayMessageOptions{MediaType: "video"},
		"relay-group-1",
		"media",
		"participant-hash",
	)
	if err != nil {
		t.Fatalf("buildRelayGroupMessageNode returned error: %v", err)
	}

	if got := node.Tag; got != "message" {
		t.Fatalf("unexpected node tag: %s", got)
	}
	if got := node.Attrs["to"]; got != groupJID {
		t.Fatalf("unexpected group to attr: %#v", got)
	}
	if got := node.Attrs["phash"]; got != "participant-hash" {
		t.Fatalf("unexpected phash attr: %#v", got)
	}

	content, ok := node.Content.([]waBinary.Node)
	if !ok {
		t.Fatalf("unexpected group node content type: %T", node.Content)
	}
	if len(content) != 2 {
		t.Fatalf("expected participants + sender key enc, got %d children", len(content))
	}
	if content[0].Tag != "participants" {
		t.Fatalf("expected first child to be participants, got %s", content[0].Tag)
	}
	if content[1].Tag != "enc" {
		t.Fatalf("expected second child to be enc, got %s", content[1].Tag)
	}
	if got := content[1].Attrs["type"]; got != string(RelayEncryptionSenderKey) {
		t.Fatalf("unexpected group enc type: %#v", got)
	}
	if got := content[1].Attrs["mediatype"]; got != "video" {
		t.Fatalf("unexpected group mediatype attr: %#v", got)
	}
	if got := string(content[1].Content.([]byte)); got != "sender-key-ciphertext" {
		t.Fatalf("unexpected sender key ciphertext payload: %q", got)
	}
}

func TestValidateRelayParticipantsRejectsInvalidInputs(t *testing.T) {
	err := validateRelayParticipants([]RelayParticipantMessage{{
		JID:            types.EmptyJID,
		EncryptionType: RelayEncryptionNormal,
		Payload:        []byte("ciphertext"),
	}})
	if err == nil {
		t.Fatal("expected empty jid validation error")
	}

	err = validateRelayParticipants([]RelayParticipantMessage{{
		JID:            types.NewJID("15551234567", types.DefaultUserServer),
		EncryptionType: RelayEncryptionNormal,
	}})
	if err == nil {
		t.Fatal("expected empty payload validation error")
	}

	err = validateRelayParticipants([]RelayParticipantMessage{{
		JID:            types.NewJID("15551234567", types.DefaultUserServer),
		EncryptionType: RelayEncryptionType("bad"),
		Payload:        []byte("ciphertext"),
	}})
	if err == nil {
		t.Fatal("expected invalid encryption type validation error")
	}
}

func TestBuildRelayRetryMessageNodeIncludesRetryAttrs(t *testing.T) {
	cli := &Client{
		Store: &store.Device{
			Account: &waAdv.ADVSignedDeviceIdentity{
				Details: []byte("device-details"),
			},
		},
	}

	node := cli.buildRelayRetryMessageNode(
		types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer},
		[]byte("retry-ciphertext"),
		RelayRetryMessageOptions{
			EncryptionType:        RelayEncryptionPreKey,
			MessageType:           "media",
			MessageID:             "retry-msg-1",
			Timestamp:             time.Unix(1700000000, 0),
			RetryCount:            3,
			MediaType:             "image",
			IncludeDeviceIdentity: true,
			IsGroup:               false,
			Participant:           types.NewJID("1234567890", types.GroupServer),
			Recipient:             types.NewJID("15551230000", types.DefaultUserServer),
			Edit:                  "7",
		},
		"media",
		time.Unix(1700000000, 0),
	)

	if got := node.Attrs["id"]; got != types.MessageID("retry-msg-1") {
		t.Fatalf("unexpected retry id: %#v", got)
	}
	if got := node.Attrs["to"]; got != (types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer}) {
		t.Fatalf("unexpected retry target: %#v", got)
	}
	if got := node.Attrs["device_fanout"]; got != false {
		t.Fatalf("unexpected device_fanout attr: %#v", got)
	}
	if got := node.Attrs["edit"]; got != "7" {
		t.Fatalf("unexpected edit attr: %#v", got)
	}

	content := node.Content.([]waBinary.Node)
	if len(content) != 2 {
		t.Fatalf("expected enc + device identity, got %d children", len(content))
	}
	if got := content[0].Attrs["count"]; got != 3 {
		t.Fatalf("unexpected retry count attr: %#v", got)
	}
	if got := content[0].Attrs["type"]; got != string(RelayEncryptionPreKey) {
		t.Fatalf("unexpected retry enc type: %#v", got)
	}
	if got := string(content[0].Content.([]byte)); got != "retry-ciphertext" {
		t.Fatalf("unexpected retry payload: %q", got)
	}
	if content[1].Tag != "device-identity" {
		t.Fatalf("expected device identity child, got %s", content[1].Tag)
	}
}
