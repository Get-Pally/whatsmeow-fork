// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"go.mau.fi/libsignal/ecc"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

var (
	AdvAccountSignaturePrefix = []byte{6, 0}
	AdvDeviceSignaturePrefix  = []byte{6, 1}

	AdvHostedAccountSignaturePrefix = []byte{6, 5}
	AdvHostedDeviceSignaturePrefix  = []byte{6, 6}
)

// RelayPairSuccessRequest is the raw pair-success payload that must be validated by the
// external companion owner in transport-only relay mode.
type RelayPairSuccessRequest struct {
	RequestID      string
	DeviceIdentity []byte
	BusinessName   string
	Platform       string
	JID            types.JID
	LID            types.JID
}

// RelayPairSuccessResponse is the validated pair-success result returned by the external
// companion owner in transport-only relay mode.
type RelayPairSuccessResponse struct {
	// Account is the full ADVSignedDeviceIdentity protobuf to persist for future device-identity nodes.
	Account []byte
	// DeviceIdentity is the self-signed ADVSignedDeviceIdentity protobuf to echo back in pair-device-sign.
	DeviceIdentity []byte
	// KeyIndex is copied into the pair-device-sign device-identity node attrs.
	KeyIndex uint32
}

func (cli *Client) handleIQ(ctx context.Context, node *waBinary.Node) {
	children := node.GetChildren()
	if len(children) != 1 || node.Attrs["from"] != types.ServerJID {
		return
	}
	switch children[0].Tag {
	case "pair-device":
		cli.handlePairDevice(ctx, node)
	case "pair-success":
		cli.handlePairSuccess(ctx, node)
	}
}

func (cli *Client) handlePairDevice(ctx context.Context, node *waBinary.Node) {
	pairDevice := node.GetChildByTag("pair-device")
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   node.Attrs["from"],
			"id":   node.Attrs["id"],
			"type": "result",
		},
	})
	if err != nil {
		cli.Log.Warnf("Failed to send acknowledgement for pair-device request: %v", err)
	}

	evt := &events.QR{Codes: make([]string, 0, len(pairDevice.GetChildren()))}
	for i, child := range pairDevice.GetChildren() {
		if child.Tag != "ref" {
			cli.Log.Warnf("pair-device node contains unexpected child tag %s at index %d", child.Tag, i)
			continue
		}
		content, ok := child.Content.([]byte)
		if !ok {
			cli.Log.Warnf("pair-device node contains unexpected child content type %T at index %d", child, i)
			continue
		}
		evt.Codes = append(evt.Codes, cli.makeQRData(string(content)))
	}

	cli.dispatchEvent(evt)
}

func (cli *Client) makeQRData(ref string) string {
	noise := base64.StdEncoding.EncodeToString(cli.Store.NoiseKey.Pub[:])
	identity := base64.StdEncoding.EncodeToString(cli.Store.IdentityKey.Pub[:])
	adv := base64.StdEncoding.EncodeToString(cli.Store.AdvSecretKey)

	// Debug: Log the identity key being used in the QR code
	cli.Log.Debugf("makeQRData: identity key hex: %x", cli.Store.IdentityKey.Pub[:])
	cli.Log.Debugf("makeQRData: noise key hex: %x", cli.Store.NoiseKey.Pub[:])

	return strings.Join([]string{ref, noise, identity, adv}, ",")
}

func (cli *Client) handlePairSuccess(ctx context.Context, node *waBinary.Node) {
	id := node.Attrs["id"].(string)
	pairSuccess := node.GetChildByTag("pair-success")

	deviceIdentityBytes, _ := pairSuccess.GetChildByTag("device-identity").Content.([]byte)
	businessName, _ := pairSuccess.GetChildByTag("biz").Attrs["name"].(string)
	jid, _ := pairSuccess.GetChildByTag("device").Attrs["jid"].(types.JID)
	lid, _ := pairSuccess.GetChildByTag("device").Attrs["lid"].(types.JID)
	platform, _ := pairSuccess.GetChildByTag("platform").Attrs["name"].(string)

	go func() {
		err := cli.handlePair(ctx, deviceIdentityBytes, id, businessName, platform, jid, lid)
		if err != nil {
			cli.Log.Errorf("Failed to pair device: %v", err)
			cli.Disconnect()
			cli.dispatchEvent(&events.PairError{ID: jid, LID: lid, BusinessName: businessName, Platform: platform, Error: err})
		} else {
			cli.Log.Infof("Successfully paired %s", cli.Store.ID)
			cli.dispatchEvent(&events.PairSuccess{ID: jid, LID: lid, BusinessName: businessName, Platform: platform})
		}
	}()
}

func (cli *Client) handlePair(ctx context.Context, deviceIdentityBytes []byte, reqID, businessName, platform string, jid, lid types.JID) error {
	if cli.IsRelayTransportMode() {
		if cli.RelayPairSuccessCallback == nil {
			cli.sendPairError(ctx, reqID, 500, "internal-error")
			return ErrRelayTransportRequiresPairSuccessCallback
		}
		return cli.handleRelayPair(ctx, deviceIdentityBytes, reqID, businessName, platform, jid, lid)
	}

	deviceIdentity, deviceIdentityDetails, err := cli.parseAndValidatePairSuccess(ctx, deviceIdentityBytes, reqID)
	if err != nil {
		return err
	}

	if cli.RelaySignCallback != nil {
		message := concatBytes(AdvDeviceSignaturePrefix, deviceIdentity.Details, cli.Store.IdentityKey.Pub[:], deviceIdentity.AccountSignatureKey)
		signature, err := cli.RelaySignCallback(message)
		if err != nil {
			cli.sendPairError(ctx, reqID, 500, "internal-error")
			return &PairProtoError{"failed to get relay signature from external signer", err}
		}
		deviceIdentity.DeviceSignature = signature[:]
	} else {
		deviceIdentity.DeviceSignature = generateDeviceSignature(deviceIdentity, cli.Store.IdentityKey)[:]
	}

	if cli.PrePairCallback != nil && !cli.PrePairCallback(jid, platform, businessName) {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return ErrPairRejectedLocally
	}

	cli.Store.Account = proto.Clone(deviceIdentity).(*waAdv.ADVSignedDeviceIdentity)

	mainDeviceLID := lid
	mainDeviceLID.Device = 0
	mainDeviceIdentity := *(*[32]byte)(deviceIdentity.AccountSignatureKey)
	deviceIdentity.AccountSignatureKey = nil

	selfSignedDeviceIdentity, err := proto.Marshal(deviceIdentity)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to marshal self-signed device identity", err}
	}

	cli.Store.ID = &jid
	cli.Store.LID = lid
	cli.Store.BusinessName = businessName
	cli.Store.Platform = platform
	err = cli.Store.Save(ctx)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairDatabaseError{"failed to save device store", err}
	}
	cli.StoreLIDPNMapping(ctx, lid, jid)
	err = cli.Store.Companion.Identities.PutIdentity(ctx, mainDeviceLID.SignalAddress().String(), mainDeviceIdentity)
	if err != nil {
		_ = cli.Store.Delete(ctx)
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairDatabaseError{"failed to store main device identity", err}
	}

	// Expect a disconnect after this and don't dispatch the usual Disconnected event
	cli.expectDisconnect()

	err = cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   types.ServerJID,
			"type": "result",
			"id":   reqID,
		},
		Content: []waBinary.Node{{
			Tag: "pair-device-sign",
			Content: []waBinary.Node{{
				Tag: "device-identity",
				Attrs: waBinary.Attrs{
					"key-index": deviceIdentityDetails.GetKeyIndex(),
				},
				Content: selfSignedDeviceIdentity,
			}},
		}},
	})
	if err != nil {
		_ = cli.Store.Delete(ctx)
		return fmt.Errorf("failed to send pairing confirmation: %w", err)
	}
	return nil
}

func (cli *Client) handleRelayPair(ctx context.Context, deviceIdentityBytes []byte, reqID, businessName, platform string, jid, lid types.JID) error {
	if cli.PrePairCallback != nil && !cli.PrePairCallback(jid, platform, businessName) {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return ErrPairRejectedLocally
	}

	originalIdentity, originalDetails, err := cli.parseAndValidatePairSuccess(ctx, deviceIdentityBytes, reqID)
	if err != nil {
		return err
	}

	resp, err := cli.RelayPairSuccessCallback(ctx, &RelayPairSuccessRequest{
		RequestID:      reqID,
		DeviceIdentity: append([]byte(nil), deviceIdentityBytes...),
		BusinessName:   businessName,
		Platform:       platform,
		JID:            jid,
		LID:            lid,
	})
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to validate pair success using relay callback", err}
	}

	account, err := cli.validateRelayPairSuccessResponse(resp, originalIdentity, originalDetails)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"relay pair success response failed server-side validation", err}
	}

	cli.Store.ID = &jid
	cli.Store.LID = lid
	cli.Store.BusinessName = businessName
	cli.Store.Platform = platform
	cli.Store.Account = proto.Clone(account).(*waAdv.ADVSignedDeviceIdentity)
	cli.Store.AdvSecretKey = nil
	// Re-apply external relay keys before saving so the app's identity key
	// and registration ID are persisted for this new device JID. Without this,
	// the fork's own generated identity key would be saved, causing prekey
	// uploads to fail with 406 after a 515 reconnect.
	if cli.RelayKeyApplyCallback != nil {
		if err := cli.RelayKeyApplyCallback(cli.Store); err != nil {
			cli.Log.Warnf("Failed to re-apply relay keys before pair save: %v", err)
		}
	}
	err = cli.Store.Save(ctx)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairDatabaseError{"failed to save device store", err}
	}
	cli.StoreLIDPNMapping(ctx, lid, jid)

	cli.expectDisconnect()

	err = cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   types.ServerJID,
			"type": "result",
			"id":   reqID,
		},
		Content: []waBinary.Node{{
			Tag: "pair-device-sign",
			Content: []waBinary.Node{{
				Tag: "device-identity",
				Attrs: waBinary.Attrs{
					"key-index": resp.KeyIndex,
				},
				Content: resp.DeviceIdentity,
			}},
		}},
	})
	if err != nil {
		_ = cli.Store.Delete(ctx)
		return fmt.Errorf("failed to send pairing confirmation: %w", err)
	}
	return nil
}

func (cli *Client) parseAndValidatePairSuccess(ctx context.Context, deviceIdentityBytes []byte, reqID string) (*waAdv.ADVSignedDeviceIdentity, *waAdv.ADVDeviceIdentity, error) {
	var deviceIdentityContainer waAdv.ADVSignedDeviceIdentityHMAC
	err := proto.Unmarshal(deviceIdentityBytes, &deviceIdentityContainer)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return nil, nil, &PairProtoError{"failed to parse device identity container in pair success message", err}
	}

	h := hmac.New(sha256.New, cli.Store.AdvSecretKey)
	if deviceIdentityContainer.GetAccountType() == waAdv.ADVEncryptionType_HOSTED {
		h.Write(AdvHostedAccountSignaturePrefix)
	}
	h.Write(deviceIdentityContainer.Details)

	if !bytes.Equal(h.Sum(nil), deviceIdentityContainer.HMAC) {
		cli.Log.Warnf("Invalid HMAC from pair success message")
		cli.sendPairError(ctx, reqID, 401, "hmac-mismatch")
		return nil, nil, ErrPairInvalidDeviceIdentityHMAC
	}

	var deviceIdentity waAdv.ADVSignedDeviceIdentity
	err = proto.Unmarshal(deviceIdentityContainer.Details, &deviceIdentity)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return nil, nil, &PairProtoError{"failed to parse signed device identity in pair success message", err}
	}

	var deviceIdentityDetails waAdv.ADVDeviceIdentity
	err = proto.Unmarshal(deviceIdentity.Details, &deviceIdentityDetails)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return nil, nil, &PairProtoError{"failed to parse device identity details in pair success message", err}
	}

	if !verifyAccountSignature(&deviceIdentity, cli.Store.IdentityKey, deviceIdentityDetails.GetDeviceType() == waAdv.ADVEncryptionType_HOSTED) {
		cli.sendPairError(ctx, reqID, 401, "signature-mismatch")
		return nil, nil, ErrPairInvalidDeviceSignature
	}

	return &deviceIdentity, &deviceIdentityDetails, nil
}

func (cli *Client) validateRelayPairSuccessResponse(resp *RelayPairSuccessResponse, originalIdentity *waAdv.ADVSignedDeviceIdentity, originalDetails *waAdv.ADVDeviceIdentity) (*waAdv.ADVSignedDeviceIdentity, error) {
	if resp == nil {
		return nil, errors.New("missing relay pair success response")
	}
	if resp.KeyIndex != originalDetails.GetKeyIndex() {
		return nil, fmt.Errorf("relay pair success key index mismatch: got %d want %d", resp.KeyIndex, originalDetails.GetKeyIndex())
	}

	var account waAdv.ADVSignedDeviceIdentity
	if err := proto.Unmarshal(resp.Account, &account); err != nil {
		return nil, &PairProtoError{"failed to parse relay account identity", err}
	}
	if len(account.GetAccountSignatureKey()) != 32 {
		return nil, &PairProtoError{"relay account identity missing account signature key", ErrPairInvalidDeviceSignature}
	}
	if !bytes.Equal(account.GetDetails(), originalIdentity.GetDetails()) {
		return nil, errors.New("relay account identity details did not match pair-success payload")
	}
	if !bytes.Equal(account.GetAccountSignatureKey(), originalIdentity.GetAccountSignatureKey()) {
		return nil, errors.New("relay account identity signature key did not match pair-success payload")
	}
	if !bytes.Equal(account.GetAccountSignature(), originalIdentity.GetAccountSignature()) {
		return nil, errors.New("relay account identity signature did not match pair-success payload")
	}
	if !verifyDeviceSignatureWithAccountKey(&account, cli.Store.IdentityKey, originalIdentity.GetAccountSignatureKey()) {
		return nil, errors.New("relay account identity device signature did not verify")
	}

	var selfSigned waAdv.ADVSignedDeviceIdentity
	if err := proto.Unmarshal(resp.DeviceIdentity, &selfSigned); err != nil {
		return nil, &PairProtoError{"failed to parse relay self-signed device identity", err}
	}
	if len(selfSigned.GetAccountSignatureKey()) != 0 {
		return nil, errors.New("relay self-signed device identity unexpectedly contained account signature key")
	}
	if !bytes.Equal(selfSigned.GetDetails(), originalIdentity.GetDetails()) {
		return nil, errors.New("relay self-signed device identity details did not match pair-success payload")
	}
	if !bytes.Equal(selfSigned.GetAccountSignature(), originalIdentity.GetAccountSignature()) {
		return nil, errors.New("relay self-signed device identity account signature did not match pair-success payload")
	}
	if !bytes.Equal(selfSigned.GetDeviceSignature(), account.GetDeviceSignature()) {
		return nil, errors.New("relay self-signed device signature did not match persisted account identity")
	}
	if !verifyDeviceSignatureWithAccountKey(&selfSigned, cli.Store.IdentityKey, originalIdentity.GetAccountSignatureKey()) {
		return nil, errors.New("relay self-signed device identity device signature did not verify")
	}

	return &account, nil
}

func concatBytes(data ...[]byte) []byte {
	length := 0
	for _, item := range data {
		length += len(item)
	}
	output := make([]byte, length)
	ptr := 0
	for _, item := range data {
		ptr += copy(output[ptr:ptr+len(item)], item)
	}
	return output
}

func verifyAccountSignature(deviceIdentity *waAdv.ADVSignedDeviceIdentity, ikp *keys.KeyPair, isHosted bool) bool {
	if len(deviceIdentity.AccountSignatureKey) != 32 || len(deviceIdentity.AccountSignature) != 64 {
		return false
	}

	signatureKey := ecc.NewDjbECPublicKey(*(*[32]byte)(deviceIdentity.AccountSignatureKey))
	signature := *(*[64]byte)(deviceIdentity.AccountSignature)

	prefix := AdvAccountSignaturePrefix
	if isHosted {
		prefix = AdvHostedAccountSignaturePrefix
	}
	message := concatBytes(prefix, deviceIdentity.Details, ikp.Pub[:])

	return ecc.VerifySignature(signatureKey, message, signature)
}

func generateDeviceSignature(deviceIdentity *waAdv.ADVSignedDeviceIdentity, ikp *keys.KeyPair) *[64]byte {
	prefix := AdvDeviceSignaturePrefix
	message := concatBytes(prefix, deviceIdentity.Details, ikp.Pub[:], deviceIdentity.AccountSignatureKey)
	sig := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*ikp.Priv), message)
	return &sig
}

func verifyDeviceSignatureWithAccountKey(deviceIdentity *waAdv.ADVSignedDeviceIdentity, ikp *keys.KeyPair, accountSignatureKey []byte) bool {
	if len(deviceIdentity.DeviceSignature) != 64 || len(accountSignatureKey) != 32 {
		return false
	}

	signatureKey := ecc.NewDjbECPublicKey(*ikp.Pub)
	signature := *(*[64]byte)(deviceIdentity.DeviceSignature)
	message := concatBytes(AdvDeviceSignaturePrefix, deviceIdentity.Details, ikp.Pub[:], accountSignatureKey)

	return ecc.VerifySignature(signatureKey, message, signature)
}

func (cli *Client) sendPairError(ctx context.Context, id string, code int, text string) {
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   types.ServerJID,
			"type": "error",
			"id":   id,
		},
		Content: []waBinary.Node{{
			Tag: "error",
			Attrs: waBinary.Attrs{
				"code": code,
				"text": text,
			},
		}},
	})
	if err != nil {
		cli.Log.Errorf("Failed to send pair error node: %v", err)
	}
}
