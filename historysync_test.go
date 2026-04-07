package whatsmeow

import (
	"context"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
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

type captureHistoryContactStore struct {
	store.NoopStore
	entries map[types.JID]store.ContactEntry
}

func newCaptureHistoryContactStore() *captureHistoryContactStore {
	return &captureHistoryContactStore{entries: make(map[types.JID]store.ContactEntry)}
}

func (s *captureHistoryContactStore) PutAllContactNames(_ context.Context, contacts []store.ContactEntry) error {
	for _, contact := range contacts {
		s.entries[contact.JID] = contact
	}
	return nil
}

type captureHistoryLIDStore struct {
	store.NoopStore
	mappings map[types.JID]types.JID
}

func newCaptureHistoryLIDStore() *captureHistoryLIDStore {
	return &captureHistoryLIDStore{mappings: make(map[types.JID]types.JID)}
}

func (s *captureHistoryLIDStore) PutManyLIDMappings(_ context.Context, mappings []store.LIDMapping) error {
	for _, mapping := range mappings {
		s.mappings[mapping.LID] = mapping.PN
	}
	return nil
}

func (s *captureHistoryLIDStore) PutLIDMapping(_ context.Context, lid, pn types.JID) error {
	s.mappings[lid] = pn
	return nil
}

type captureHistoryChatSettingsStore struct {
	store.NoopStore
	archived map[types.JID]bool
	pinned   map[types.JID]bool
	muted    map[types.JID]time.Time
}

func newCaptureHistoryChatSettingsStore() *captureHistoryChatSettingsStore {
	return &captureHistoryChatSettingsStore{
		archived: make(map[types.JID]bool),
		pinned:   make(map[types.JID]bool),
		muted:    make(map[types.JID]time.Time),
	}
}

func (s *captureHistoryChatSettingsStore) PutArchived(_ context.Context, chat types.JID, archived bool) error {
	s.archived[chat] = archived
	return nil
}

func (s *captureHistoryChatSettingsStore) PutPinned(_ context.Context, chat types.JID, pinned bool) error {
	s.pinned[chat] = pinned
	return nil
}

func (s *captureHistoryChatSettingsStore) PutMutedUntil(_ context.Context, chat types.JID, mutedUntil time.Time) error {
	s.muted[chat] = mutedUntil
	return nil
}

func TestStoreHistoricalConversationMetadataStoresDirectChatNamesAndMappings(t *testing.T) {
	contacts := newCaptureHistoryContactStore()
	lids := newCaptureHistoryLIDStore()
	chatSettings := newCaptureHistoryChatSettingsStore()
	cli := &Client{
		Log: waLog.Noop,
		Store: &store.Device{
			Contacts:     contacts,
			LIDs:         lids,
			ChatSettings: chatSettings,
		},
	}

	cli.storeHistoricalConversationMetadata(context.Background(), []*waHistorySync.Conversation{
		{
			ID:          proto.String("120363421559461991@g.us"),
			Archived:    proto.Bool(true),
			DisplayName: proto.String("YC S25"),
		},
		{
			ID:          proto.String("15551230000@s.whatsapp.net"),
			Archived:    proto.Bool(false),
			Pinned:      proto.Uint32(1),
			MuteEndTime: proto.Uint64(1_777_777_777),
			DisplayName: proto.String("Alice Example"),
		},
		{
			ID:          proto.String("100021903081555@lid"),
			PnJID:       proto.String("15551230000@s.whatsapp.net"),
			LidJID:      proto.String("100021903081555@lid"),
			Archived:    proto.Bool(false),
			Pinned:      proto.Uint32(1),
			MuteEndTime: proto.Uint64(1_777_777_777),
			DisplayName: proto.String("Alice Example"),
		},
		{
			LidJID:      proto.String("100021903081556@lid"),
			DisplayName: proto.String("Bob Example"),
		},
	})

	wantContacts := map[types.JID]store.ContactEntry{
		types.NewJID("15551230000", types.DefaultUserServer): {
			JID:       types.NewJID("15551230000", types.DefaultUserServer),
			FirstName: "Alice Example",
			FullName:  "Alice Example",
		},
		types.NewJID("100021903081555", types.HiddenUserServer): {
			JID:       types.NewJID("100021903081555", types.HiddenUserServer),
			FirstName: "Alice Example",
			FullName:  "Alice Example",
		},
		types.NewJID("100021903081556", types.HiddenUserServer): {
			JID:       types.NewJID("100021903081556", types.HiddenUserServer),
			FirstName: "Bob Example",
			FullName:  "Bob Example",
		},
	}
	if !reflect.DeepEqual(contacts.entries, wantContacts) {
		t.Fatalf("unexpected contacts from history sync:\n got  %#v\n want %#v", contacts.entries, wantContacts)
	}

	wantMappings := map[types.JID]types.JID{
		types.NewJID("100021903081555", types.HiddenUserServer): types.NewJID("15551230000", types.DefaultUserServer),
	}
	if !reflect.DeepEqual(lids.mappings, wantMappings) {
		t.Fatalf("unexpected PN-LID mappings from history sync:\n got  %#v\n want %#v", lids.mappings, wantMappings)
	}

	wantArchived := map[types.JID]bool{
		types.NewJID("120363421559461991", types.GroupServer):   true,
		types.NewJID("15551230000", types.DefaultUserServer):    false,
		types.NewJID("100021903081555", types.HiddenUserServer): false,
	}
	if !reflect.DeepEqual(chatSettings.archived, wantArchived) {
		t.Fatalf("unexpected archived chat settings from history sync:\n got  %#v\n want %#v", chatSettings.archived, wantArchived)
	}

	wantPinned := map[types.JID]bool{
		types.NewJID("15551230000", types.DefaultUserServer):    true,
		types.NewJID("100021903081555", types.HiddenUserServer): true,
	}
	if !reflect.DeepEqual(chatSettings.pinned, wantPinned) {
		t.Fatalf("unexpected pinned chat settings from history sync:\n got  %#v\n want %#v", chatSettings.pinned, wantPinned)
	}

	wantMuted := map[types.JID]time.Time{
		types.NewJID("15551230000", types.DefaultUserServer):    time.Unix(1_777_777_777, 0),
		types.NewJID("100021903081555", types.HiddenUserServer): time.Unix(1_777_777_777, 0),
	}
	if !reflect.DeepEqual(chatSettings.muted, wantMuted) {
		t.Fatalf("unexpected muted chat settings from history sync:\n got  %#v\n want %#v", chatSettings.muted, wantMuted)
	}
}
