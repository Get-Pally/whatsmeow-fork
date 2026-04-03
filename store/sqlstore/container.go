// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	mathRand "math/rand/v2"

	"github.com/google/uuid"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/random"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore/upgrades"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Container is a wrapper for a SQL database that can contain multiple whatsmeow sessions.
type Container struct {
	db     *dbutil.Database
	log    waLog.Logger
	LIDMap *CachedLIDMap
}

var _ store.DeviceContainer = (*Container)(nil)

// New connects to the given SQL database and wraps it in a Container.
//
// Only SQLite and Postgres are currently fully supported.
//
// The logger can be nil and will default to a no-op logger.
//
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	container, err := sqlstore.New(context.Background(), "sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
func New(ctx context.Context, dialect, address string, log waLog.Logger) (*Container, error) {
	db, err := sql.Open(dialect, address)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	container := NewWithDB(db, dialect, log)
	err = container.Upgrade(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade database: %w", err)
	}
	return container, nil
}

// NewWithDB wraps an existing SQL connection in a Container.
//
// Only SQLite and Postgres are currently fully supported.
//
// The logger can be nil and will default to a no-op logger.
//
// When using SQLite, it's strongly recommended to enable foreign keys by adding `?_foreign_keys=true`:
//
//	db, err := sql.Open("sqlite3", "file:yoursqlitefile.db?_foreign_keys=on")
//	if err != nil {
//	    panic(err)
//	}
//	container := sqlstore.NewWithDB(db, "sqlite3", nil)
//
// This method does not call Upgrade automatically like New does, so you must call it yourself:
//
//	container := sqlstore.NewWithDB(...)
//	err := container.Upgrade()
func NewWithDB(db *sql.DB, dialect string, log waLog.Logger) *Container {
	wrapped, err := dbutil.NewWithDB(db, dialect)
	if err != nil {
		// This will only panic if the dialect is invalid
		panic(err)
	}
	wrapped.UpgradeTable = upgrades.Table
	wrapped.VersionTable = "whatsmeow_version"
	return NewWithWrappedDB(wrapped, log)
}

func NewWithWrappedDB(wrapped *dbutil.Database, log waLog.Logger) *Container {
	if log == nil {
		log = waLog.Noop
	}
	return &Container{
		db:     wrapped,
		log:    log,
		LIDMap: NewCachedLIDMap(wrapped),
	}
}

// Upgrade upgrades the database from the current to the latest version available.
func (c *Container) Upgrade(ctx context.Context) error {
	if c.db.Dialect == dbutil.SQLite {
		var foreignKeysEnabled bool
		err := c.db.QueryRow(ctx, "PRAGMA foreign_keys").Scan(&foreignKeysEnabled)
		if err != nil {
			return fmt.Errorf("failed to check if foreign keys are enabled: %w", err)
		} else if !foreignKeysEnabled {
			return fmt.Errorf("foreign keys are not enabled")
		}
	}

	return c.db.Upgrade(ctx)
}

const getAllDevicesQuery = `
SELECT jid, lid, registration_id, transport_only, noise_key, identity_key,
       signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
       adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
       platform, business_name, push_name, facebook_uuid, lid_migration_ts
FROM whatsmeow_device
`

const getDeviceQuery = getAllDevicesQuery + " WHERE jid=$1"

func (c *Container) scanDevice(row dbutil.Scannable) (*store.Device, error) {
	var device store.Device
	device.Log = c.log
	device.SignedPreKey = &keys.PreKey{}
	var noisePriv, identityData, preKeyData, preKeySig []byte
	var account waAdv.ADVSignedDeviceIdentity
	var fbUUID uuid.NullUUID

	err := row.Scan(
		&device.ID, &device.LID, &device.RegistrationID, &device.TransportOnly, &noisePriv, &identityData,
		&preKeyData, &device.SignedPreKey.KeyID, &preKeySig,
		&device.AdvSecretKey, &account.Details, &account.AccountSignature, &account.AccountSignatureKey, &account.DeviceSignature,
		&device.Platform, &device.BusinessName, &device.PushName, &fbUUID, &device.LIDMigrationTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to scan session: %w", err)
	} else if len(noisePriv) != 32 || len(identityData) != 32 || len(preKeyData) != 32 || len(preKeySig) != 64 {
		return nil, ErrInvalidLength
	}

	device.NoiseKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(noisePriv))
	if device.TransportOnly {
		if !isAllZeroBytes(identityData) {
			device.IdentityKey = &keys.KeyPair{Pub: (*[32]byte)(identityData)}
		}
		if !isAllZeroBytes(preKeyData) || !isAllZeroBytes(preKeySig) || device.SignedPreKey.KeyID != 0 {
			device.SignedPreKey.KeyPair = keys.KeyPair{Pub: (*[32]byte)(preKeyData)}
			device.SignedPreKey.Signature = (*[64]byte)(preKeySig)
		} else {
			device.SignedPreKey = nil
		}
		if isAllZeroBytes(device.AdvSecretKey) {
			device.AdvSecretKey = nil
		}
		if len(account.Details) == 0 && isAllZeroBytes(account.AccountSignature) && isAllZeroBytes(account.AccountSignatureKey) && isAllZeroBytes(account.DeviceSignature) {
			device.Account = nil
		} else {
			device.Account = &account
		}
	} else {
		device.IdentityKey = keys.NewKeyPairFromPrivateKey(*(*[32]byte)(identityData))
		device.SignedPreKey.KeyPair = *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(preKeyData))
		device.SignedPreKey.Signature = (*[64]byte)(preKeySig)
		device.Account = &account
	}
	device.FacebookUUID = fbUUID.UUID

	c.initializeDevice(&device)

	return &device, nil
}

// GetAllDevices finds all the devices in the database.
func (c *Container) GetAllDevices(ctx context.Context) ([]*store.Device, error) {
	res, err := c.db.Query(ctx, getAllDevicesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	sessions := make([]*store.Device, 0)
	for res.Next() {
		sess, scanErr := c.scanDevice(res)
		if scanErr != nil {
			return sessions, scanErr
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// GetFirstDevice is a convenience method for getting the first device in the store. If there are
// no devices, then a new device will be created. You should only use this if you don't want to
// have multiple sessions simultaneously.
func (c *Container) GetFirstDevice(ctx context.Context) (*store.Device, error) {
	devices, err := c.GetAllDevices(ctx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return c.NewDevice(), nil
	} else {
		return devices[0], nil
	}
}

// GetDevice finds the device with the specified JID in the database.
//
// If the device is not found, nil is returned instead.
//
// Note that the parameter usually must be an AD-JID.
func (c *Container) GetDevice(ctx context.Context, jid types.JID) (*store.Device, error) {
	sess, err := c.scanDevice(c.db.QueryRow(ctx, getDeviceQuery, jid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return sess, err
}

const (
	insertDeviceQuery = `
			INSERT INTO whatsmeow_device (jid, lid, registration_id, transport_only, noise_key, identity_key,
										  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
										  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig,
										  platform, business_name, push_name, facebook_uuid, lid_migration_ts)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
			ON CONFLICT (jid) DO UPDATE
				SET lid=excluded.lid,
					transport_only=excluded.transport_only,
					platform=excluded.platform,
					business_name=excluded.business_name,
					push_name=excluded.push_name,
				lid_migration_ts=excluded.lid_migration_ts
	`
	deleteDeviceQuery        = `DELETE FROM whatsmeow_device WHERE jid=$1`
	deletePrivacyTokensQuery = `DELETE FROM whatsmeow_privacy_tokens WHERE our_jid=$1`
	countDevicesQuery        = `SELECT COUNT(*) FROM whatsmeow_device`
)

// NewDevice creates a new device in this database.
//
// No data is actually stored before Save is called. However, the pairing process will automatically
// call Save after a successful pairing, so you most likely don't need to call it yourself.
func (c *Container) NewDevice() *store.Device {
	device := &store.Device{
		Log:       c.log,
		Container: c,

		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: mathRand.Uint32(),
		AdvSecretKey:   random.Bytes(32),
	}
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
	return device
}

// NewTransportOnlyDevice creates a transport-only device shell for relay mode.
// It intentionally omits companion Signal bootstrap material so the backend never
// generates decrypt-capable identity state for the external client.
func (c *Container) NewTransportOnlyDevice() *store.Device {
	return &store.Device{
		Log:           c.log,
		Container:     c,
		NoiseKey:      keys.NewKeyPair(),
		TransportOnly: true,
	}
}

// ErrDeviceIDMustBeSet is the error returned by PutDevice if you try to save a device before knowing its JID.
var ErrDeviceIDMustBeSet = errors.New("device JID must be known before accessing database")

// Close will close the container's database
func (c *Container) Close() error {
	if c != nil && c.db != nil {
		return c.db.Close()
	}
	return nil
}

// PutDevice stores the given device in this database. This should be called through Device.Save()
// (which usually doesn't need to be called manually, as the library does that automatically when relevant).
func (c *Container) PutDevice(ctx context.Context, device *store.Device) error {
	if device.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	var registrationID uint32
	identityBytes := make([]byte, 32)
	signedPreKeyBytes := make([]byte, 32)
	signedPreKeyID := uint32(0)
	signedPreKeySig := make([]byte, 64)
	if !device.TransportOnly {
		registrationID = device.RegistrationID
		if device.IdentityKey == nil || device.IdentityKey.Priv == nil || device.SignedPreKey == nil || device.SignedPreKey.Priv == nil || device.SignedPreKey.Signature == nil {
			return fmt.Errorf("full device save requires local identity and signed pre-key private material")
		}
		identityBytes = device.IdentityKey.Priv[:]
		signedPreKeyBytes = device.SignedPreKey.Priv[:]
		signedPreKeyID = device.SignedPreKey.KeyID
		signedPreKeySig = device.SignedPreKey.Signature[:]
	} else if device.SignedPreKey != nil && device.SignedPreKey.Signature != nil {
		// Transport-only devices intentionally do not persist companion Signal bootstrap material.
		// The live bridge session may still attach public keys in memory when needed.
		signedPreKeySig = make([]byte, 64)
	}
	advKey := make([]byte, 32)
	advDetails := []byte{}
	advAccountSig := make([]byte, 64)
	advAccountSigKey := make([]byte, 32)
	advDeviceSig := make([]byte, 64)
	if !device.TransportOnly && len(device.AdvSecretKey) == 32 {
		advKey = device.AdvSecretKey
	}
	if device.Account != nil {
		advDetails = device.Account.Details
		if len(device.Account.AccountSignature) == 64 {
			advAccountSig = device.Account.AccountSignature
		}
		if len(device.Account.AccountSignatureKey) == 32 {
			advAccountSigKey = device.Account.AccountSignatureKey
		}
		if len(device.Account.DeviceSignature) == 64 {
			advDeviceSig = device.Account.DeviceSignature
		}
	}
	_, err := c.db.Exec(ctx, insertDeviceQuery,
		device.ID, device.LID, registrationID, device.TransportOnly, device.NoiseKey.Priv[:], identityBytes,
		signedPreKeyBytes, signedPreKeyID, signedPreKeySig,
		advKey, advDetails, advAccountSig, advAccountSigKey, advDeviceSig,
		device.Platform, device.BusinessName, device.PushName, uuid.NullUUID{UUID: device.FacebookUUID, Valid: device.FacebookUUID != uuid.Nil},
		device.LIDMigrationTimestamp,
	)

	if !device.Initialized {
		c.initializeDevice(device)
	}
	return err
}

func isAllZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func (c *Container) initializeDevice(device *store.Device) {
	innerStore := NewSQLStore(c, *device.ID)
	device.Contacts = innerStore
	device.ChatSettings = innerStore
	if device.TransportOnly {
		transportOnlyStore := store.NewTransportOnlyNoopStore()
		device.Companion.Identities = transportOnlyStore
		device.Companion.Sessions = transportOnlyStore
		if device.PreKeys == nil {
			device.PreKeys = transportOnlyStore
		}
		device.Companion.SenderKeys = transportOnlyStore
		device.Companion.AppStateKeys = innerStore
		device.Companion.AppState = innerStore
		device.Companion.MsgSecrets = transportOnlyStore
		device.Companion.PrivacyTokens = transportOnlyStore
		device.EventBuffer = transportOnlyStore
	} else {
		device.Companion.Identities = innerStore
		device.Companion.Sessions = innerStore
		device.PreKeys = innerStore
		device.Companion.SenderKeys = innerStore
		device.Companion.AppStateKeys = innerStore
		device.Companion.AppState = innerStore
		device.Companion.MsgSecrets = innerStore
		device.Companion.PrivacyTokens = innerStore
		device.EventBuffer = innerStore
	}
	device.LIDs = c.LIDMap
	device.Container = c
	device.Initialized = true
}

// DeleteDevice deletes the given device from this database. This should be called through Device.Delete()
func (c *Container) DeleteDevice(ctx context.Context, store *store.Device) error {
	if store.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	return c.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		_, err := c.db.Exec(ctx, deletePrivacyTokensQuery, store.ID)
		if err != nil {
			return err
		}

		_, err = c.db.Exec(ctx, deleteDeviceQuery, store.ID)
		if err != nil {
			return err
		}

		var remainingDevices int
		err = c.db.QueryRow(ctx, countDevicesQuery).Scan(&remainingDevices)
		if err != nil {
			return err
		}
		if remainingDevices == 0 && c.LIDMap != nil {
			return c.LIDMap.DeleteAll(ctx)
		}
		return nil
	})
}
