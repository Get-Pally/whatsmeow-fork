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

func TestTransportOnlyDeviceRoundTripUsesPublicKeysOnly(t *testing.T) {
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
			device.RegistrationID,
			true,
			noiseKey.Priv[:],
			identityPub[:],
			signedPreKeyPub[:],
			device.SignedPreKey.KeyID,
			signedPreKeySig[:],
			device.AdvSecretKey[:],
			device.Account.Details,
			device.Account.AccountSignature,
			device.Account.AccountSignatureKey,
			device.Account.DeviceSignature,
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
		device.RegistrationID,
		true,
		noiseKey.Priv[:],
		identityPub[:],
		signedPreKeyPub[:],
		device.SignedPreKey.KeyID,
		signedPreKeySig[:],
		device.AdvSecretKey[:],
		device.Account.Details,
		device.Account.AccountSignature,
		device.Account.AccountSignatureKey,
		device.Account.DeviceSignature,
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
	if loaded.IdentityKey == nil || loaded.IdentityKey.Pub == nil {
		t.Fatal("expected loaded device to keep identity public key")
	}
	if loaded.IdentityKey.Priv != nil {
		t.Fatal("expected loaded device identity private key to remain nil")
	}
	if got := loaded.IdentityKey.Pub[:]; string(got) != string(identityPub[:]) {
		t.Fatalf("unexpected loaded identity public key: %x", got)
	}
	if loaded.SignedPreKey == nil || loaded.SignedPreKey.Pub == nil {
		t.Fatal("expected loaded device to keep signed pre-key public key")
	}
	if loaded.SignedPreKey.Priv != nil {
		t.Fatal("expected loaded signed pre-key private key to remain nil")
	}
	if got := loaded.SignedPreKey.Pub[:]; string(got) != string(signedPreKeyPub[:]) {
		t.Fatalf("unexpected loaded signed pre-key public key: %x", got)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sqlmock expectations were not met: %v", err)
	}
}
