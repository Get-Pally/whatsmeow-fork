package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

func TestDeleteDeviceClearsAllSessionTablesAndGlobalMappingsWhenLastDeviceIsRemoved(t *testing.T) {
	container := newSQLiteTestContainer(t)
	ctx := context.Background()

	device, jid, lid := newSavedTestDevice(t, ctx, container, "15551234567")
	contactPN := types.NewJID("15550001111", types.DefaultUserServer)
	contactLID := types.NewJID("15550001111", types.HiddenUserServer)
	populateDeviceData(t, ctx, container, jid, lid, contactPN, contactLID)

	if err := container.LIDMap.FillCache(ctx); err != nil {
		t.Fatalf("failed to warm LID cache: %v", err)
	}
	loadedLID, err := container.LIDMap.GetLIDForPN(ctx, contactPN)
	if err != nil {
		t.Fatalf("failed to load cached LID mapping: %v", err)
	}
	if loadedLID != contactLID {
		t.Fatalf("expected cached LID %s, got %s", contactLID, loadedLID)
	}

	if err := device.Delete(ctx); err != nil {
		t.Fatalf("failed to delete device: %v", err)
	}

	for _, table := range []string{
		"whatsmeow_device",
		"whatsmeow_identity_keys",
		"whatsmeow_pre_keys",
		"whatsmeow_sessions",
		"whatsmeow_sender_keys",
		"whatsmeow_app_state_sync_keys",
		"whatsmeow_app_state_version",
		"whatsmeow_app_state_mutation_macs",
		"whatsmeow_contacts",
		"whatsmeow_chat_settings",
		"whatsmeow_message_secrets",
		"whatsmeow_privacy_tokens",
		"whatsmeow_lid_map",
		"whatsmeow_event_buffer",
	} {
		if got := countRows(t, ctx, container, table); got != 0 {
			t.Fatalf("expected %s to be empty after deleting the last device, got %d rows", table, got)
		}
	}

	loadedLID, err = container.LIDMap.GetLIDForPN(ctx, contactPN)
	if err != nil {
		t.Fatalf("failed to read LID mapping after delete: %v", err)
	}
	if loadedLID != types.EmptyJID {
		t.Fatalf("expected LID cache to be cleared after delete, got %s", loadedLID)
	}
}

func TestDeleteDevicePreservesGlobalMappingsWhileOtherDevicesRemain(t *testing.T) {
	container := newSQLiteTestContainer(t)
	ctx := context.Background()

	device1, jid1, _ := newSavedTestDevice(t, ctx, container, "15551230001")
	_, jid2, _ := newSavedTestDevice(t, ctx, container, "15551230002")
	contactPN := types.NewJID("15550002222", types.DefaultUserServer)
	contactLID := types.NewJID("15550002222", types.HiddenUserServer)

	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_privacy_tokens (our_jid, their_jid, token, timestamp) VALUES ($1, $2, $3, $4)`,
		jid1.String(), contactPN.String(), bytesOfLen(32, 1), time.Now().Unix(),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_privacy_tokens (our_jid, their_jid, token, timestamp) VALUES ($1, $2, $3, $4)`,
		jid2.String(), contactPN.String(), bytesOfLen(32, 2), time.Now().Unix(),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_lid_map (lid, pn) VALUES ($1, $2)`,
		contactLID.User, contactPN.User,
	)

	if err := device1.Delete(ctx); err != nil {
		t.Fatalf("failed to delete first device: %v", err)
	}

	if got := countRowsWhere(t, ctx, container, "whatsmeow_device", "jid=$1", jid1.String()); got != 0 {
		t.Fatalf("expected deleted device row to be gone, got %d rows", got)
	}
	if got := countRowsWhere(t, ctx, container, "whatsmeow_device", "jid=$1", jid2.String()); got != 1 {
		t.Fatalf("expected second device row to remain, got %d rows", got)
	}
	if got := countRowsWhere(t, ctx, container, "whatsmeow_privacy_tokens", "our_jid=$1", jid1.String()); got != 0 {
		t.Fatalf("expected deleted device privacy tokens to be gone, got %d rows", got)
	}
	if got := countRowsWhere(t, ctx, container, "whatsmeow_privacy_tokens", "our_jid=$1", jid2.String()); got != 1 {
		t.Fatalf("expected remaining device privacy tokens to stay, got %d rows", got)
	}
	if got := countRows(t, ctx, container, "whatsmeow_lid_map"); got != 1 {
		t.Fatalf("expected global LID mappings to stay while another device remains, got %d rows", got)
	}
}

func TestGetDeviceMatchesExactJIDOnly(t *testing.T) {
	container := newSQLiteTestContainer(t)
	ctx := context.Background()

	phoneJID := types.NewJID("15551239999", types.DefaultUserServer)
	deviceJID := types.JID{User: phoneJID.User, Device: 7, Server: phoneJID.Server}

	phoneDevice := container.NewDevice()
	phoneDevice.ID = &phoneJID
	if err := phoneDevice.Save(ctx); err != nil {
		t.Fatalf("failed to save phone device: %v", err)
	}

	adDevice := container.NewDevice()
	adDevice.ID = &deviceJID
	if err := adDevice.Save(ctx); err != nil {
		t.Fatalf("failed to save AD device: %v", err)
	}

	loadedPhone, err := container.GetDevice(ctx, phoneJID)
	if err != nil {
		t.Fatalf("failed to load phone device: %v", err)
	}
	if loadedPhone == nil || loadedPhone.ID == nil || loadedPhone.ID.String() != phoneJID.String() {
		t.Fatalf("expected exact phone JID match %s, got %#v", phoneJID, loadedPhone)
	}

	loadedAD, err := container.GetDevice(ctx, deviceJID)
	if err != nil {
		t.Fatalf("failed to load AD device: %v", err)
	}
	if loadedAD == nil || loadedAD.ID == nil || loadedAD.ID.String() != deviceJID.String() {
		t.Fatalf("expected exact AD JID match %s, got %#v", deviceJID, loadedAD)
	}

	otherDeviceJID := types.JID{User: phoneJID.User, Device: 8, Server: phoneJID.Server}
	loadedOther, err := container.GetDevice(ctx, otherDeviceJID)
	if err != nil {
		t.Fatalf("failed to load non-existent sibling AD device: %v", err)
	}
	if loadedOther != nil {
		t.Fatalf("expected no match for sibling AD JID %s, got %s", otherDeviceJID, loadedOther.ID)
	}
}

func newSQLiteTestContainer(t *testing.T) *Container {
	t.Helper()

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=memory&cache=shared&_foreign_keys=on", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	container := NewWithDB(db, "sqlite3", nil)
	schema, err := os.ReadFile("upgrades/00-latest-schema.sql")
	if err != nil {
		t.Fatalf("failed to read sqlite test schema: %v", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("failed to initialize sqlite test schema: %v", err)
	}

	t.Cleanup(func() {
		_ = container.Close()
	})
	return container
}

func newSavedTestDevice(t *testing.T, ctx context.Context, container *Container, phone string) (*store.Device, types.JID, types.JID) {
	t.Helper()

	jid := types.NewJID(phone, types.DefaultUserServer)
	lid := types.NewJID(phone, types.HiddenUserServer)
	device := container.NewDevice()
	device.ID = &jid
	device.LID = lid
	if err := device.Save(ctx); err != nil {
		t.Fatalf("failed to save test device: %v", err)
	}
	return device, jid, lid
}

func populateDeviceData(t *testing.T, ctx context.Context, container *Container, jid, lid, contactPN, contactLID types.JID) {
	t.Helper()

	now := time.Now().Unix()
	hash := bytesOfLen(128, 7)
	ciphertextHash := bytesOfLen(32, 11)

	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_identity_keys (our_jid, their_id, identity) VALUES ($1, $2, $3)`,
		jid.String(), "15550003333@s.whatsapp.net:1", bytesOfLen(32, 1),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_pre_keys (jid, key_id, key, uploaded) VALUES ($1, $2, $3, $4)`,
		jid.String(), 1, bytesOfLen(32, 2), false,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_sessions (our_jid, their_id, session) VALUES ($1, $2, $3)`,
		jid.String(), "15550004444@s.whatsapp.net:1", []byte("session"),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, sender_key) VALUES ($1, $2, $3, $4)`,
		jid.String(), "15550005555@g.us", "15550006666@s.whatsapp.net:1", []byte("sender-key"),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_app_state_sync_keys (jid, key_id, key_data, timestamp, fingerprint) VALUES ($1, $2, $3, $4, $5)`,
		jid.String(), bytesOfLen(4, 3), []byte("app-state-key"), now, bytesOfLen(32, 4),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_app_state_version (jid, name, version, hash) VALUES ($1, $2, $3, $4)`,
		jid.String(), "settings_sync", 1, hash,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_app_state_mutation_macs (jid, name, version, index_mac, value_mac) VALUES ($1, $2, $3, $4, $5)`,
		jid.String(), "settings_sync", 1, bytesOfLen(32, 5), bytesOfLen(32, 6),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_contacts (our_jid, their_jid, first_name, full_name, push_name, business_name, redacted_phone) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		jid.String(), contactPN.String(), "Test", "Test Contact", "Push", "Biz", "+1 ***",
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_chat_settings (our_jid, chat_jid, muted_until, pinned, archived) VALUES ($1, $2, $3, $4, $5)`,
		jid.String(), contactPN.String(), now, true, false,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_message_secrets (our_jid, chat_jid, sender_jid, message_id, key) VALUES ($1, $2, $3, $4, $5)`,
		jid.String(), contactPN.String(), contactPN.String(), "message-1", bytesOfLen(32, 8),
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_privacy_tokens (our_jid, their_jid, token, timestamp) VALUES ($1, $2, $3, $4)`,
		jid.String(), contactPN.String(), bytesOfLen(32, 9), now,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_lid_map (lid, pn) VALUES ($1, $2)`,
		lid.User, jid.User,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_lid_map (lid, pn) VALUES ($1, $2)`,
		contactLID.User, contactPN.User,
	)
	mustExec(t, ctx, container,
		`INSERT INTO whatsmeow_event_buffer (our_jid, ciphertext_hash, plaintext, server_timestamp, insert_timestamp) VALUES ($1, $2, $3, $4, $5)`,
		jid.String(), ciphertextHash, []byte("plaintext"), now, now,
	)
}

func mustExec(t *testing.T, ctx context.Context, container *Container, query string, args ...any) {
	t.Helper()
	if _, err := container.db.Exec(ctx, query, args...); err != nil {
		t.Fatalf("failed to exec query %q: %v", query, err)
	}
}

func countRows(t *testing.T, ctx context.Context, container *Container, table string) int {
	t.Helper()
	return countRowsWhere(t, ctx, container, table, "1=1")
}

func countRowsWhere(t *testing.T, ctx context.Context, container *Container, table, where string, args ...any) int {
	t.Helper()

	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", table, where)
	if err := container.db.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		t.Fatalf("failed to count rows for %s: %v", table, err)
	}
	return count
}

func bytesOfLen(length int, seed byte) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = seed + byte(i)
	}
	return data
}
