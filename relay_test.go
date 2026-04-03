package whatsmeow

import (
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
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
		RelayMessageOptions{Metadata: MessageNodeMetadata{Type: "media", MediaType: "image"}},
		"relay-msg-1",
		MessageNodeMetadata{Type: "media", MediaType: "image"},
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
		RelayMessageOptions{Metadata: MessageNodeMetadata{Type: "media", MediaType: "video"}},
		"relay-group-1",
		MessageNodeMetadata{Type: "media", MediaType: "video"},
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
			MessageID:             "retry-msg-1",
			Timestamp:             time.Unix(1700000000, 0),
			RetryCount:            3,
			Metadata:              MessageNodeMetadata{Type: "media", MediaType: "image", Edit: types.EditAttributeSenderRevoke},
			IncludeDeviceIdentity: true,
			IsGroup:               false,
			Participant:           types.NewJID("1234567890", types.GroupServer),
			Recipient:             types.NewJID("15551230000", types.DefaultUserServer),
		},
		MessageNodeMetadata{Type: "media", MediaType: "image", Edit: types.EditAttributeSenderRevoke},
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

func TestBuildMessageNodeMetadataCoversRelayRelevantMessageTypes(t *testing.T) {
	appStateSyncReq := &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST.Enum(),
		},
	}
	historySyncReq := &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
			PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
				PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_HISTORY_SYNC_ON_DEMAND.Enum(),
			},
		},
	}

	tests := []struct {
		name         string
		message      *waE2E.Message
		opts         MessageNodeMetadataOptions
		wantType     string
		wantMedia    string
		wantPollType string
		wantButton   string
		wantDecrypt  events.DecryptFailMode
		wantExtraKey string
		wantExtraVal any
	}{
		{
			name:      "location",
			message:   &waE2E.Message{LocationMessage: &waE2E.LocationMessage{}},
			wantType:  "media",
			wantMedia: "location",
		},
		{
			name:         "poll vote",
			message:      &waE2E.Message{PollUpdateMessage: &waE2E.PollUpdateMessage{}},
			wantType:     "poll",
			wantPollType: "vote",
			wantDecrypt:  events.DecryptFailHide,
		},
		{
			name: "list",
			message: &waE2E.Message{ListMessage: &waE2E.ListMessage{
				ListType: waE2E.ListMessage_SINGLE_SELECT.Enum(),
			}},
			wantType:   "media",
			wantMedia:  "list",
			wantButton: "list",
		},
		{
			name:         "peer app state sync",
			message:      appStateSyncReq,
			opts:         MessageNodeMetadataOptions{Peer: true},
			wantType:     "text",
			wantExtraKey: "push_priority",
			wantExtraVal: "high",
		},
		{
			name:         "peer history sync request",
			message:      historySyncReq,
			opts:         MessageNodeMetadataOptions{Peer: true},
			wantType:     "text",
			wantExtraKey: "privacy_sensitive",
			wantExtraVal: "1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildMessageNodeMetadata(tc.message, tc.opts)
			if got.Type != tc.wantType {
				t.Fatalf("unexpected type: got %q want %q", got.Type, tc.wantType)
			}
			if got.MediaType != tc.wantMedia {
				t.Fatalf("unexpected media type: got %q want %q", got.MediaType, tc.wantMedia)
			}
			if got.PollType != tc.wantPollType {
				t.Fatalf("unexpected poll type: got %q want %q", got.PollType, tc.wantPollType)
			}
			if got.ButtonType != tc.wantButton {
				t.Fatalf("unexpected button type: got %q want %q", got.ButtonType, tc.wantButton)
			}
			if got.DecryptFail != tc.wantDecrypt {
				t.Fatalf("unexpected decrypt-fail: got %q want %q", got.DecryptFail, tc.wantDecrypt)
			}
			if tc.wantExtraKey != "" && got.ExtraMessageAttrs[tc.wantExtraKey] != tc.wantExtraVal {
				t.Fatalf("unexpected extra attr %q: %#v", tc.wantExtraKey, got.ExtraMessageAttrs[tc.wantExtraKey])
			}
		})
	}
}

func TestBuildRelayMessageNodeAppendsCanonicalPollAndBizNodes(t *testing.T) {
	cli := &Client{}
	to := types.NewJID("15551234567", types.DefaultUserServer)

	listMetadata := BuildMessageNodeMetadata(&waE2E.Message{
		ListMessage: &waE2E.ListMessage{
			ListType: waE2E.ListMessage_SINGLE_SELECT.Enum(),
		},
	}, MessageNodeMetadataOptions{})
	listNode, err := cli.buildRelayMessageNode(
		to,
		[]RelayParticipantMessage{{
			JID:            types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer},
			EncryptionType: RelayEncryptionNormal,
			Payload:        []byte("ciphertext"),
		}},
		RelayMessageOptions{Metadata: listMetadata},
		"relay-list-1",
		listMetadata,
	)
	if err != nil {
		t.Fatalf("buildRelayMessageNode(list) returned error: %v", err)
	}
	listContent := listNode.Content.([]waBinary.Node)
	if len(listContent) != 2 {
		t.Fatalf("expected participants + biz node, got %d children", len(listContent))
	}
	if listContent[1].Tag != "biz" {
		t.Fatalf("expected biz child, got %s", listContent[1].Tag)
	}
	bizChildren := listContent[1].Content.([]waBinary.Node)
	if bizChildren[0].Tag != "list" {
		t.Fatalf("expected list biz child, got %s", bizChildren[0].Tag)
	}
	if got := bizChildren[0].Attrs["type"]; got != "single_select" {
		t.Fatalf("unexpected list biz attrs: %#v", bizChildren[0].Attrs)
	}
	participantChildren := listContent[0].Content.([]waBinary.Node)
	listEnc := participantChildren[0].Content.([]waBinary.Node)[0]
	if got := listEnc.Attrs["mediatype"]; got != "list" {
		t.Fatalf("unexpected list mediatype: %#v", got)
	}

	pollMetadata := BuildMessageNodeMetadata(&waE2E.Message{
		PollUpdateMessage: &waE2E.PollUpdateMessage{},
	}, MessageNodeMetadataOptions{})
	pollNode, err := cli.buildRelayMessageNode(
		to,
		[]RelayParticipantMessage{{
			JID:            types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer},
			EncryptionType: RelayEncryptionNormal,
			Payload:        []byte("poll-ciphertext"),
		}},
		RelayMessageOptions{Metadata: pollMetadata},
		"relay-poll-1",
		pollMetadata,
	)
	if err != nil {
		t.Fatalf("buildRelayMessageNode(poll) returned error: %v", err)
	}
	pollContent := pollNode.Content.([]waBinary.Node)
	if len(pollContent) != 2 {
		t.Fatalf("expected participants + poll meta, got %d children", len(pollContent))
	}
	if pollContent[1].Tag != "meta" || pollContent[1].Attrs["polltype"] != "vote" {
		t.Fatalf("unexpected poll meta node: %#v", pollContent[1])
	}
	pollParticipants := pollContent[0].Content.([]waBinary.Node)
	pollEnc := pollParticipants[0].Content.([]waBinary.Node)[0]
	if got := pollEnc.Attrs["decrypt-fail"]; got != string(events.DecryptFailHide) {
		t.Fatalf("unexpected poll decrypt-fail attr: %#v", got)
	}
}

func TestBuildRelayRetryMessageNodeAppendsCanonicalPollMetadata(t *testing.T) {
	cli := &Client{}
	metadata := BuildMessageNodeMetadata(&waE2E.Message{
		PollUpdateMessage: &waE2E.PollUpdateMessage{},
	}, MessageNodeMetadataOptions{})

	node := cli.buildRelayRetryMessageNode(
		types.JID{User: "15551234567", Device: 7, Server: types.DefaultUserServer},
		[]byte("retry-ciphertext"),
		RelayRetryMessageOptions{
			EncryptionType: RelayEncryptionNormal,
			Metadata:       metadata,
			MessageID:      "retry-poll-1",
			RetryCount:     1,
		},
		metadata,
		time.Unix(1700000000, 0),
	)

	content := node.Content.([]waBinary.Node)
	if len(content) != 2 {
		t.Fatalf("expected enc + poll meta, got %d children", len(content))
	}
	if content[1].Tag != "meta" || content[1].Attrs["polltype"] != "vote" {
		t.Fatalf("unexpected retry poll meta node: %#v", content[1])
	}
	if got := content[0].Attrs["decrypt-fail"]; got != string(events.DecryptFailHide) {
		t.Fatalf("unexpected retry decrypt-fail attr: %#v", got)
	}
}
