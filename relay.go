// Copyright (c) 2024 Pally Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"fmt"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// RelayEncryptionType represents the type of Signal Protocol encryption used
type RelayEncryptionType string

const (
	// RelayEncryptionPreKey is for pre-key messages (first message in a session)
	RelayEncryptionPreKey RelayEncryptionType = "pkmsg"
	// RelayEncryptionNormal is for normal Signal messages (established session)
	RelayEncryptionNormal RelayEncryptionType = "msg"
	// RelayEncryptionSenderKey is for group messages using sender keys
	RelayEncryptionSenderKey RelayEncryptionType = "skmsg"
)

// RelayMessageOptions configures a pre-encrypted relay message
type RelayMessageOptions struct {
	// EncryptionType specifies the Signal Protocol message type
	// Must be one of: "pkmsg" (pre-key), "msg" (normal), or "skmsg" (sender key)
	EncryptionType RelayEncryptionType

	// MessageType is the WhatsApp message type attribute (e.g., "text", "media")
	// Defaults to "text" if empty
	MessageType string

	// Timestamp is when the message was created. Defaults to now if zero.
	Timestamp time.Time

	// MessageID is the message identifier. Generated if empty.
	MessageID types.MessageID

	// MediaType is optional media type for media messages (e.g., "image", "video")
	MediaType string

	// IncludeDeviceIdentity includes device identity node for pre-key messages
	// This is typically needed for the first message in a session
	IncludeDeviceIdentity bool
}

// RelayMessageResponse contains the result of sending a relay message
type RelayMessageResponse struct {
	// ID is the message ID that was sent
	ID types.MessageID

	// Timestamp is when the message was sent
	Timestamp time.Time

	// ServerData is the raw response data from the server
	ServerData []byte
}

// SendRelayMessage sends a message that was encrypted by an external entity.
//
// This is intended for relay mode where the server acts as a relay and does not
// own the Signal Protocol keys. The iOS client encrypts messages locally and
// sends the pre-encrypted ciphertext to the server, which then forwards it to
// WhatsApp without re-encrypting.
//
// The preEncryptedPayload must be a valid Signal Protocol ciphertext that was
// encrypted for the recipient's device using proper Signal sessions.
//
// Example usage:
//
//	opts := whatsmeow.RelayMessageOptions{
//	    EncryptionType: whatsmeow.RelayEncryptionNormal,
//	    MessageType:    "text",
//	}
//	resp, err := client.SendRelayMessage(ctx, recipientJID, encryptedBytes, opts)
func (cli *Client) SendRelayMessage(
	ctx context.Context,
	to types.JID,
	preEncryptedPayload []byte,
	opts RelayMessageOptions,
) (*RelayMessageResponse, error) {
	// Validate recipient JID
	if to.IsEmpty() {
		return nil, fmt.Errorf("recipient JID is required")
	}

	// Validate encryption type
	switch opts.EncryptionType {
	case RelayEncryptionPreKey, RelayEncryptionNormal, RelayEncryptionSenderKey:
		// Valid
	case "":
		return nil, fmt.Errorf("encryption type is required")
	default:
		return nil, fmt.Errorf("invalid encryption type: %s (must be pkmsg, msg, or skmsg)", opts.EncryptionType)
	}

	// Validate payload
	if len(preEncryptedPayload) == 0 {
		return nil, fmt.Errorf("pre-encrypted payload cannot be empty")
	}

	// Generate message ID if not provided
	msgID := opts.MessageID
	if msgID == "" {
		msgID = cli.GenerateMessageID()
	}

	// Use provided timestamp or now
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Default message type
	msgType := opts.MessageType
	if msgType == "" {
		msgType = "text"
	}

	// Build the message node
	node := cli.buildRelayMessageNode(to, preEncryptedPayload, opts, msgID, msgType)

	// Send via existing infrastructure
	data, err := cli.sendNodeAndGetData(ctx, *node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay message: %w", err)
	}

	return &RelayMessageResponse{
		ID:         msgID,
		Timestamp:  ts,
		ServerData: data,
	}, nil
}

// buildRelayMessageNode constructs a message binary node with pre-encrypted content.
// This bypasses the normal encryption pipeline and uses the provided ciphertext directly.
func (cli *Client) buildRelayMessageNode(
	to types.JID,
	encryptedPayload []byte,
	opts RelayMessageOptions,
	msgID types.MessageID,
	msgType string,
) *waBinary.Node {
	// Build the <enc> node with pre-encrypted content
	encAttrs := waBinary.Attrs{
		"v":    "2",
		"type": string(opts.EncryptionType),
	}

	// Add media type if specified
	if opts.MediaType != "" {
		encAttrs["mediatype"] = opts.MediaType
	}

	encNode := waBinary.Node{
		Tag:     "enc",
		Attrs:   encAttrs,
		Content: encryptedPayload,
	}

	// Build the <to> wrapper for the participant
	toNode := waBinary.Node{
		Tag: "to",
		Attrs: waBinary.Attrs{
			"jid": to.String(),
		},
		Content: []waBinary.Node{encNode},
	}

	// Build the <participants> wrapper
	participantsNode := waBinary.Node{
		Tag:     "participants",
		Content: []waBinary.Node{toNode},
	}

	// Build the main message attributes
	attrs := waBinary.Attrs{
		"id":   msgID,
		"type": msgType,
		"to":   to,
	}

	// Build content array
	content := []waBinary.Node{participantsNode}

	// Include device identity for pre-key messages if requested
	if opts.IncludeDeviceIdentity && opts.EncryptionType == RelayEncryptionPreKey {
		content = append(content, cli.makeDeviceIdentityNode())
	}

	return &waBinary.Node{
		Tag:     "message",
		Attrs:   attrs,
		Content: content,
	}
}

// SendRelayGroupMessage sends a pre-encrypted group message using sender keys.
//
// For group messages, the ciphertext should be encrypted using the sender's
// sender key for the group. The phash (participant hash) is used for consistency
// checks by WhatsApp.
func (cli *Client) SendRelayGroupMessage(
	ctx context.Context,
	groupJID types.JID,
	preEncryptedPayload []byte,
	opts RelayMessageOptions,
	phash string,
) (*RelayMessageResponse, error) {
	// Validate group JID
	if groupJID.IsEmpty() {
		return nil, fmt.Errorf("group JID is required")
	}

	// Validate payload
	if len(preEncryptedPayload) == 0 {
		return nil, fmt.Errorf("pre-encrypted payload cannot be empty")
	}

	// Force sender key encryption type for groups
	if opts.EncryptionType != RelayEncryptionSenderKey {
		opts.EncryptionType = RelayEncryptionSenderKey
	}

	// Generate message ID if not provided
	msgID := opts.MessageID
	if msgID == "" {
		msgID = cli.GenerateMessageID()
	}

	// Use provided timestamp or now
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	// Default message type
	msgType := opts.MessageType
	if msgType == "" {
		msgType = "text"
	}

	// Build the group message node (different structure than DM)
	node := cli.buildRelayGroupMessageNode(groupJID, preEncryptedPayload, opts, msgID, msgType, phash)

	// Send via existing infrastructure
	data, err := cli.sendNodeAndGetData(ctx, *node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay group message: %w", err)
	}

	return &RelayMessageResponse{
		ID:         msgID,
		Timestamp:  ts,
		ServerData: data,
	}, nil
}

// buildRelayGroupMessageNode constructs a group message node with pre-encrypted sender key content.
func (cli *Client) buildRelayGroupMessageNode(
	groupJID types.JID,
	encryptedPayload []byte,
	opts RelayMessageOptions,
	msgID types.MessageID,
	msgType string,
	phash string,
) *waBinary.Node {
	// Build the <enc> node with sender key encrypted content
	encAttrs := waBinary.Attrs{
		"v":    "2",
		"type": "skmsg",
	}

	// Add media type if specified
	if opts.MediaType != "" {
		encAttrs["mediatype"] = opts.MediaType
	}

	encNode := waBinary.Node{
		Tag:     "enc",
		Attrs:   encAttrs,
		Content: encryptedPayload,
	}

	// Build the main message attributes
	attrs := waBinary.Attrs{
		"id":    msgID,
		"type":  msgType,
		"to":    groupJID,
		"phash": phash,
	}

	return &waBinary.Node{
		Tag:     "message",
		Attrs:   attrs,
		Content: []waBinary.Node{encNode},
	}
}
