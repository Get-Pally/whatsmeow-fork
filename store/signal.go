// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"

	"go.mau.fi/libsignal/ecc"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/state/store"
)

var SignalProtobufSerializer = serialize.NewProtoBufSerializer()

var _ store.SignalProtocol = (*Device)(nil)

func (device *Device) transportOnlySignalError(op string) error {
	return fmt.Errorf("%s unavailable: %w", op, ErrTransportOnlyStoreOperation)
}

func (device *Device) GetIdentityKeyPair() *identity.KeyPair {
	if device.TransportOnly || device.IdentityKey == nil || device.IdentityKey.Priv == nil {
		panic(device.transportOnlySignalError("identity key access"))
	}
	return identity.NewKeyPair(
		identity.NewKey(ecc.NewDjbECPublicKey(*device.IdentityKey.Pub)),
		ecc.NewDjbECPrivateKey(*device.IdentityKey.Priv),
	)
}

func (device *Device) GetLocalRegistrationID() uint32 {
	return device.RegistrationID
}

func (device *Device) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) error {
	if device.TransportOnly {
		return device.transportOnlySignalError("identity persistence")
	}
	addrString := address.String()
	err := device.Companion.Identities.PutIdentity(ctx, addrString, identityKey.PublicKey().PublicKey())
	if err != nil {
		return fmt.Errorf("failed to save identity of %s: %w", addrString, err)
	}
	return nil
}

func (device *Device) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) (bool, error) {
	if device.TransportOnly {
		return false, device.transportOnlySignalError("identity trust check")
	}
	addrString := address.String()
	isTrusted, err := device.Companion.Identities.IsTrustedIdentity(ctx, addrString, identityKey.PublicKey().PublicKey())
	if err != nil {
		return false, fmt.Errorf("failed to check if %s's identity is trusted: %w", addrString, err)
	}
	return isTrusted, nil
}

func (device *Device) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error) {
	if device.TransportOnly {
		return nil, device.transportOnlySignalError("pre-key load")
	}
	preKey, err := device.PreKeys.GetPreKey(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to load prekey %d: %w", id, err)
	}
	if preKey == nil {
		return nil, nil
	}
	return record.NewPreKey(preKey.KeyID, ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(*preKey.Pub),
		ecc.NewDjbECPrivateKey(*preKey.Priv),
	), nil), nil
}

func (device *Device) RemovePreKey(ctx context.Context, id uint32) error {
	if device.TransportOnly {
		return device.transportOnlySignalError("pre-key removal")
	}
	err := device.PreKeys.RemovePreKey(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to remove prekey %d: %w", id, err)
	}
	return nil
}

func (device *Device) StorePreKey(ctx context.Context, preKeyID uint32, preKeyRecord *record.PreKey) error {
	panic("not implemented")
}

func (device *Device) ContainsPreKey(ctx context.Context, preKeyID uint32) (bool, error) {
	panic("not implemented")
}

func (device *Device) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error) {
	if device.TransportOnly {
		return nil, device.transportOnlySignalError("session load")
	}
	addrString := address.String()
	if sess := getCachedSession(ctx, addrString); sess != nil {
		return sess, nil
	}

	rawSess, err := device.Companion.Sessions.GetSession(ctx, addrString)
	if err != nil {
		return nil, fmt.Errorf("failed to load session with %s: %w", addrString, err)
	}
	if rawSess == nil {
		return record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State), nil
	}
	sess, err := record.NewSessionFromBytes(rawSess, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize session with %s: %w", addrString, err)
	}
	return sess, nil
}

func (device *Device) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	panic("not implemented")
}

func (device *Device) StoreSession(ctx context.Context, address *protocol.SignalAddress, record *record.Session) error {
	if device.TransportOnly {
		return device.transportOnlySignalError("session persistence")
	}
	addrString := address.String()
	if putCachedSession(ctx, addrString, record) {
		return nil
	}

	err := device.Companion.Sessions.PutSession(ctx, addrString, record.Serialize())
	if err != nil {
		return fmt.Errorf("failed to store session with %s: %w", addrString, err)
	}
	return nil
}

func (device *Device) ContainsSession(ctx context.Context, remoteAddress *protocol.SignalAddress) (bool, error) {
	if device.TransportOnly {
		return false, device.transportOnlySignalError("session lookup")
	}
	addrString := remoteAddress.String()
	hasSession, err := device.Companion.Sessions.HasSession(ctx, addrString)
	if err != nil {
		return false, fmt.Errorf("failed to check if store has session for %s: %w", addrString, err)
	}
	return hasSession, nil
}

func (device *Device) DeleteSession(ctx context.Context, remoteAddress *protocol.SignalAddress) error {
	panic("not implemented")
}

func (device *Device) DeleteAllSessions(ctx context.Context) error {
	panic("not implemented")
}

func (device *Device) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*record.SignedPreKey, error) {
	if device.TransportOnly || device.SignedPreKey == nil || device.SignedPreKey.Priv == nil {
		return nil, device.transportOnlySignalError("signed pre-key load")
	}
	if signedPreKeyID == device.SignedPreKey.KeyID {
		return record.NewSignedPreKey(signedPreKeyID, 0, ecc.NewECKeyPair(
			ecc.NewDjbECPublicKey(*device.SignedPreKey.Pub),
			ecc.NewDjbECPrivateKey(*device.SignedPreKey.Priv),
		), *device.SignedPreKey.Signature, nil), nil
	}
	return nil, nil
}

func (device *Device) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	panic("not implemented")
}

func (device *Device) StoreSignedPreKey(ctx context.Context, signedPreKeyID uint32, record *record.SignedPreKey) error {
	panic("not implemented")
}

func (device *Device) ContainsSignedPreKey(ctx context.Context, signedPreKeyID uint32) (bool, error) {
	panic("not implemented")
}

func (device *Device) RemoveSignedPreKey(ctx context.Context, signedPreKeyID uint32) error {
	panic("not implemented")
}

func (device *Device) StoreSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	if device.TransportOnly {
		return device.transportOnlySignalError("sender-key persistence")
	}
	groupID := senderKeyName.GroupID()
	senderString := senderKeyName.Sender().String()
	err := device.Companion.SenderKeys.PutSenderKey(ctx, groupID, senderString, keyRecord.Serialize())
	if err != nil {
		return fmt.Errorf("failed to store sender key from %s for %s: %w", senderString, groupID, err)
	}
	return nil
}

func (device *Device) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	if device.TransportOnly {
		return nil, device.transportOnlySignalError("sender-key load")
	}
	groupID := senderKeyName.GroupID()
	senderString := senderKeyName.Sender().String()
	rawKey, err := device.Companion.SenderKeys.GetSenderKey(ctx, groupID, senderString)
	if err != nil {
		return nil, fmt.Errorf("failed to load sender key from %s for %s: %w", senderString, groupID, err)
	}
	if rawKey == nil {
		return groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState), nil
	}
	key, err := groupRecord.NewSenderKeyFromBytes(rawKey, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize sender key from %s for %s: %w", senderString, groupID, err)
	}
	return key, nil
}
