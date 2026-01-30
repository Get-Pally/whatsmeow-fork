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
	cli.Log.Infof("E2EE handlePairDevice: received pair-device request from WhatsApp")
	pairDevice := node.GetChildByTag("pair-device")
	refCount := len(pairDevice.GetChildren())
	cli.Log.Debugf("E2EE handlePairDevice: %d ref codes received", refCount)

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

	cli.Log.Infof("E2EE handlePairDevice: dispatching %d QR codes to event handlers", len(evt.Codes))
	cli.dispatchEvent(evt)
}

func (cli *Client) makeQRData(ref string) string {
	noise := base64.StdEncoding.EncodeToString(cli.Store.NoiseKey.Pub[:])
	identity := base64.StdEncoding.EncodeToString(cli.Store.IdentityKey.Pub[:])
	adv := base64.StdEncoding.EncodeToString(cli.Store.AdvSecretKey)

	// Log all keys being used in the QR code (Info level for visibility)
	cli.Log.Infof("E2EE makeQRData: QR code components:")
	cli.Log.Infof("E2EE makeQRData:   identity key hex: %x", cli.Store.IdentityKey.Pub[:])
	cli.Log.Infof("E2EE makeQRData:   noise key hex: %x", cli.Store.NoiseKey.Pub[:])
	cli.Log.Infof("E2EE makeQRData:   adv secret key hex: %x", cli.Store.AdvSecretKey)
	cli.Log.Infof("E2EE makeQRData:   registration ID: %d", cli.Store.RegistrationID)
	cli.Log.Debugf("E2EE makeQRData:   ref prefix: %s...", ref[:min(20, len(ref))])

	return strings.Join([]string{ref, noise, identity, adv}, ",")
}

func (cli *Client) handlePairSuccess(ctx context.Context, node *waBinary.Node) {
	cli.Log.Infof("E2EE handlePairSuccess: received pair-success message")
	id := node.Attrs["id"].(string)
	pairSuccess := node.GetChildByTag("pair-success")

	deviceIdentityBytes, _ := pairSuccess.GetChildByTag("device-identity").Content.([]byte)
	cli.Log.Infof("E2EE handlePairSuccess: device identity bytes len=%d", len(deviceIdentityBytes))
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
	var deviceIdentityContainer waAdv.ADVSignedDeviceIdentityHMAC
	err := proto.Unmarshal(deviceIdentityBytes, &deviceIdentityContainer)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to parse device identity container in pair success message", err}
	}

	h := hmac.New(sha256.New, cli.Store.AdvSecretKey)
	if deviceIdentityContainer.GetAccountType() == waAdv.ADVEncryptionType_HOSTED {
		h.Write(AdvHostedAccountSignaturePrefix)
		//cli.Store.IsHosted = true
	}
	h.Write(deviceIdentityContainer.Details)

	if !bytes.Equal(h.Sum(nil), deviceIdentityContainer.HMAC) {
		cli.Log.Warnf("Invalid HMAC from pair success message")
		cli.sendPairError(ctx, reqID, 401, "hmac-mismatch")
		return ErrPairInvalidDeviceIdentityHMAC
	}

	var deviceIdentity waAdv.ADVSignedDeviceIdentity
	err = proto.Unmarshal(deviceIdentityContainer.Details, &deviceIdentity)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to parse signed device identity in pair success message", err}
	}

	var deviceIdentityDetails waAdv.ADVDeviceIdentity
	err = proto.Unmarshal(deviceIdentity.Details, &deviceIdentityDetails)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to parse device identity details in pair success message", err}
	}

	cli.Log.Infof("E2EE handlePair: verifying account signature with identity key hex: %x", cli.Store.IdentityKey.Pub[:8])
	if !verifyAccountSignature(&deviceIdentity, cli.Store.IdentityKey, deviceIdentityDetails.GetDeviceType() == waAdv.ADVEncryptionType_HOSTED) {
		cli.Log.Errorf("E2EE handlePair: account signature verification FAILED")
		cli.sendPairError(ctx, reqID, 401, "signature-mismatch")
		return ErrPairInvalidDeviceSignature
	}
	cli.Log.Infof("E2EE handlePair: account signature verification PASSED")

	// Generate device signature - use relay callback if available (for external identity key)
	cli.Log.Infof("E2EE handlePair: RelaySignCallback is set: %v", cli.RelaySignCallback != nil)
	if cli.RelaySignCallback != nil {
		// Build the message that needs to be signed (same format as generateDeviceSignature)
		message := concatBytes(AdvDeviceSignaturePrefix, deviceIdentity.Details, cli.Store.IdentityKey.Pub[:], deviceIdentity.AccountSignatureKey)
		cli.Log.Infof("E2EE relay: requesting external signature for device identity (message len: %d, identity key hex: %x)", len(message), cli.Store.IdentityKey.Pub[:8])
		signature, err := cli.RelaySignCallback(message)
		if err != nil {
			cli.Log.Errorf("E2EE relay: failed to get external signature: %v", err)
			cli.sendPairError(ctx, reqID, 500, "internal-error")
			return &PairProtoError{"failed to get relay signature from external signer", err}
		}
		cli.Log.Infof("E2EE relay: received external signature successfully (sig len: %d)", len(signature))
		deviceIdentity.DeviceSignature = signature[:]
	} else {
		deviceIdentity.DeviceSignature = generateDeviceSignature(&deviceIdentity, cli.Store.IdentityKey)[:]
	}

	if cli.PrePairCallback != nil && !cli.PrePairCallback(jid, platform, businessName) {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return ErrPairRejectedLocally
	}

	cli.Store.Account = proto.Clone(&deviceIdentity).(*waAdv.ADVSignedDeviceIdentity)

	mainDeviceLID := lid
	mainDeviceLID.Device = 0
	mainDeviceIdentity := *(*[32]byte)(deviceIdentity.AccountSignatureKey)
	deviceIdentity.AccountSignatureKey = nil

	selfSignedDeviceIdentity, err := proto.Marshal(&deviceIdentity)
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
	err = cli.Store.Identities.PutIdentity(ctx, mainDeviceLID.SignalAddress().String(), mainDeviceIdentity)
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
