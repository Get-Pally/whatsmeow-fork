package sqlstore

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

type stubPreKeyStore struct{}

func (s *stubPreKeyStore) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	return nil, nil
}

func (s *stubPreKeyStore) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	return nil, nil
}

func (s *stubPreKeyStore) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	return nil, nil
}

func (s *stubPreKeyStore) RemovePreKey(ctx context.Context, id uint32) error {
	return nil
}

func (s *stubPreKeyStore) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	return nil
}

func (s *stubPreKeyStore) UploadedPreKeyCount(ctx context.Context) (int, error) {
	return 0, nil
}

func TestTransportOnlyDeviceRoundTripDoesNotPersistCompanionBootstrapKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock database: %v", err)
	}
	defer db.Close()

	container := NewWithDB(db, "postgres", nil)
	ctx := context.Background()

	jid := types.NewJID("15551234567", types.DefaultUserServer)
	lid := types.NewJID("15551234567", types.HiddenUserServer)
	noiseKey := keys.NewKeyPair()
	var identityPub [32]byte
	var signedPreKeyPub [32]byte
	var signedPreKeySig [64]byte
	for i := range identityPub {
		identityPub[i] = byte(i + 1)
		signedPreKeyPub[i] = byte(i + 33)
	}
	for i := range signedPreKeySig {
		signedPreKeySig[i] = byte(i + 65)
	}
	device := &store.Device{
		Container:             container,
		ID:                    &jid,
		LID:                   lid,
		RegistrationID:        31337,
		TransportOnly:         true,
		NoiseKey:              noiseKey,
		IdentityKey:           &keys.KeyPair{Pub: &identityPub},
		SignedPreKey:          &keys.PreKey{KeyID: 21, KeyPair: keys.KeyPair{Pub: &signedPreKeyPub}, Signature: &signedPreKeySig},
		AdvSecretKey:          []byte{1, 2, 3, 4},
		Platform:              "ios",
		BusinessName:          "Test Business",
		PushName:              "Test Device",
		Account:               &waAdv.ADVSignedDeviceIdentity{Details: []byte("details"), AccountSignature: []byte("account-signature"), AccountSignatureKey: []byte("account-key"), DeviceSignature: []byte("device-signature")},
		FacebookUUID:          uuid.Nil,
		LIDMigrationTimestamp: time.Unix(0, 0).UTC().Unix(),
	}

	mock.ExpectExec(regexp.QuoteMeta(insertDeviceQuery)).
		WithArgs(
			jid,
			lid,
			uint32(0),
			true,
			noiseKey.Priv[:],
			make([]byte, 32),
			make([]byte, 32),
			uint32(0),
			make([]byte, 64),
			make([]byte, 32),
			[]byte{},
			make([]byte, 64),
			make([]byte, 32),
			make([]byte, 64),
			device.Platform,
			device.BusinessName,
			device.PushName,
			uuid.NullUUID{UUID: uuid.Nil, Valid: false},
			device.LIDMigrationTimestamp,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err = device.Save(ctx); err != nil {
		t.Fatalf("failed to save device: %v", err)
	}

	rows := sqlmock.NewRows([]string{
		"jid", "lid", "registration_id", "transport_only", "noise_key", "identity_key",
		"signed_pre_key", "signed_pre_key_id", "signed_pre_key_sig",
		"adv_key", "adv_details", "adv_account_sig", "adv_account_sig_key", "adv_device_sig",
		"platform", "business_name", "push_name", "facebook_uuid", "lid_migration_ts",
	}).AddRow(
		jid,
		lid,
		0,
		true,
		noiseKey.Priv[:],
		make([]byte, 32),
		make([]byte, 32),
		0,
		make([]byte, 64),
		make([]byte, 32),
		[]byte{},
		make([]byte, 64),
		make([]byte, 32),
		make([]byte, 64),
		device.Platform,
		device.BusinessName,
		device.PushName,
		nil,
		device.LIDMigrationTimestamp,
	)
	mock.ExpectQuery(regexp.QuoteMeta(getDeviceQuery)).WithArgs(jid).WillReturnRows(rows)

	loaded, err := container.GetDevice(ctx, jid)
	if err != nil {
		t.Fatalf("failed to load device: %v", err)
	}
	if !loaded.TransportOnly {
		t.Fatal("expected loaded device to remain transport-only")
	}
	if loaded.RegistrationID != 0 {
		t.Fatalf("expected registration id to be scrubbed, got %d", loaded.RegistrationID)
	}
	if loaded.IdentityKey != nil {
		t.Fatalf("expected transport-only reload to omit companion identity public key, got %#v", loaded.IdentityKey)
	}
	if loaded.SignedPreKey != nil {
		t.Fatalf("expected transport-only reload to omit companion signed pre-key, got %#v", loaded.SignedPreKey)
	}
	if loaded.AdvSecretKey != nil {
		t.Fatalf("expected transport-only reload to omit adv secret, got %x", loaded.AdvSecretKey)
	}
	if loaded.Account != nil {
		t.Fatalf("expected transport-only reload to omit adv account, got %#v", loaded.Account)
	}
	if _, ok := loaded.Companion.Identities.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only identity store to be a noop store, got %T", loaded.Companion.Identities)
	}
	if _, ok := loaded.Companion.Sessions.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only session store to be a noop store, got %T", loaded.Companion.Sessions)
	}
	if _, ok := loaded.Companion.SenderKeys.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only sender-key store to be a noop store, got %T", loaded.Companion.SenderKeys)
	}
	if _, ok := loaded.Companion.AppStateKeys.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only appstate-key store to be a noop store, got %T", loaded.Companion.AppStateKeys)
	}
	if _, ok := loaded.Companion.MsgSecrets.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only msg-secret store to be a noop store, got %T", loaded.Companion.MsgSecrets)
	}
	if _, ok := loaded.Companion.PrivacyTokens.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only privacy-token store to be a noop store, got %T", loaded.Companion.PrivacyTokens)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sqlmock expectations were not met: %v", err)
	}
}

func TestTransportOnlyInitializeDevicePreservesExternalPreKeyStore(t *testing.T) {
	container := &Container{}
	externalPreKeys := &stubPreKeyStore{}
	jid := types.NewJID("15551234567", types.DefaultUserServer)

	device := &store.Device{
		ID:            &jid,
		TransportOnly: true,
		PreKeys:       externalPreKeys,
	}

	container.initializeDevice(device)

	if device.PreKeys != externalPreKeys {
		t.Fatalf("expected transport-only device to preserve external pre-key store, got %T", device.PreKeys)
	}
	if _, ok := device.Companion.Identities.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only identity store to be noop after initialization, got %T", device.Companion.Identities)
	}
	if _, ok := device.Companion.AppState.(*store.NoopStore); !ok {
		t.Fatalf("expected transport-only appstate store to be noop after initialization, got %T", device.Companion.AppState)
	}
}

func TestNewTransportOnlyDeviceOmitsCompanionBootstrapMaterial(t *testing.T) {
	container := &Container{}

	device := container.NewTransportOnlyDevice()

	if !device.TransportOnly {
		t.Fatal("expected transport-only device")
	}
	if device.NoiseKey == nil || device.NoiseKey.Priv == nil {
		t.Fatal("expected transport-only device to generate only a noise key")
	}
	if device.IdentityKey != nil {
		t.Fatalf("expected transport-only device to omit identity key, got %#v", device.IdentityKey)
	}
	if device.SignedPreKey != nil {
		t.Fatalf("expected transport-only device to omit signed pre-key, got %#v", device.SignedPreKey)
	}
	if device.RegistrationID != 0 {
		t.Fatalf("expected transport-only device registration id to be zero, got %d", device.RegistrationID)
	}
	if device.AdvSecretKey != nil {
		t.Fatalf("expected transport-only device to omit adv secret, got %x", device.AdvSecretKey)
	}
	if device.Account != nil {
		t.Fatalf("expected transport-only device to omit adv account, got %#v", device.Account)
	}
}
