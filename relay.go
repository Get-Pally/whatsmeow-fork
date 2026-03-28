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

// RelayEncryptionType represents the type of Signal Protocol encryption used.
type RelayEncryptionType string

const (
	// RelayEncryptionPreKey is for pre-key messages (first message in a session).
	RelayEncryptionPreKey RelayEncryptionType = "pkmsg"
	// RelayEncryptionNormal is for normal Signal messages (established session).
	RelayEncryptionNormal RelayEncryptionType = "msg"
	// RelayEncryptionSenderKey is for group messages using sender keys.
	RelayEncryptionSenderKey RelayEncryptionType = "skmsg"
)

// RelayParticipantMessage is one per-device encrypted payload in a relay send.
type RelayParticipantMessage struct {
	JID            types.JID
	EncryptionType RelayEncryptionType
	Payload        []byte
	MediaType      string
}

// RelayMessageOptions configures a pre-encrypted relay message.
type RelayMessageOptions struct {
	// EncryptionType specifies the Signal Protocol message type for legacy single-device sends.
	EncryptionType RelayEncryptionType

	// MessageType is the WhatsApp message type attribute (e.g. "text", "media").
	// Defaults to "text" if empty.
	MessageType string

	// Timestamp is when the message was created. Defaults to now if zero.
	Timestamp time.Time

	// MessageID is the message identifier. Generated if empty.
	MessageID types.MessageID

	// MediaType is optional media type for media messages (e.g. "image", "video").
	MediaType string

	// IncludeDeviceIdentity includes device identity node for pre-key messages.
	IncludeDeviceIdentity bool

	// AdditionalNodes are appended to the message node content after participants/device identity.
	AdditionalNodes []waBinary.Node
}

// RelayRetryMessageOptions configures a retry replay message.
type RelayRetryMessageOptions struct {
	EncryptionType        RelayEncryptionType
	MessageType           string
	MessageID             types.MessageID
	Timestamp             time.Time
	RetryCount            int
	MediaType             string
	IncludeDeviceIdentity bool
	IsGroup               bool
	Participant           types.JID
	Recipient             types.JID
	Edit                  string
}

// RelayMessageResponse contains the result of sending a relay message.
type RelayMessageResponse struct {
	// ID is the message ID that was sent.
	ID types.MessageID

	// Timestamp is when the server acknowledged the message.
	Timestamp time.Time

	// ServerID is the server-assigned message id if the server returned one.
	ServerID types.MessageServerID

	// ParticipantHash is the participant hash echoed by the server, if any.
	ParticipantHash string

	// ServerData is the raw ack node from the server.
	ServerData []byte

	// SentNode is the raw outbound node that was transmitted to WhatsApp.
	SentNode []byte
}

// SendRelayNode sends a fully client-built binary node through the transport unchanged.
//
// The node must already contain the message id and any required transport attributes.
func (cli *Client) SendRelayNode(
	ctx context.Context,
	node *waBinary.Node,
	fallbackTimestamp time.Time,
) (*RelayMessageResponse, error) {
	if node == nil {
		return nil, fmt.Errorf("relay node is required")
	}
	ag := node.AttrGetter()
	msgID := ag.OptionalString("id")
	if msgID == "" {
		return nil, fmt.Errorf("relay node is missing message id")
	}
	if fallbackTimestamp.IsZero() {
		fallbackTimestamp = ag.UnixTime("t")
		if fallbackTimestamp.IsZero() {
			fallbackTimestamp = time.Now()
		}
	}
	resp, err := cli.sendRelayNodeAndWait(ctx, types.MessageID(msgID), fallbackTimestamp, node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay node: %w", err)
	}
	return resp, nil
}

// RelayParticipantHash calculates the WhatsApp participant hash used in relay sends.
func RelayParticipantHash(participants []types.JID) string {
	return participantListHashV2(participants)
}

// SendRelayMessage sends a message that was encrypted by an external entity for a single device.
//
// This is a compatibility wrapper around SendRelayMultiDeviceMessage.
func (cli *Client) SendRelayMessage(
	ctx context.Context,
	to types.JID,
	preEncryptedPayload []byte,
	opts RelayMessageOptions,
) (*RelayMessageResponse, error) {
	err := validateRelayEncryptionType(opts.EncryptionType)
	if err != nil {
		return nil, err
	}
	return cli.SendRelayMultiDeviceMessage(ctx, to, []RelayParticipantMessage{{
		JID:            to,
		EncryptionType: opts.EncryptionType,
		Payload:        preEncryptedPayload,
		MediaType:      opts.MediaType,
	}}, opts)
}

// SendRelayMultiDeviceMessage sends a pre-encrypted message with an explicit participant fanout.
func (cli *Client) SendRelayMultiDeviceMessage(
	ctx context.Context,
	to types.JID,
	participants []RelayParticipantMessage,
	opts RelayMessageOptions,
) (*RelayMessageResponse, error) {
	if to.IsEmpty() {
		return nil, fmt.Errorf("recipient JID is required")
	}
	if len(participants) == 0 {
		return nil, fmt.Errorf("at least one relay participant is required")
	}

	msgID, ts, msgType := cli.normalizeRelayMessageOptions(&opts)
	node, err := cli.buildRelayMessageNode(to, participants, opts, msgID, msgType)
	if err != nil {
		return nil, err
	}

	resp, err := cli.sendRelayNodeAndWait(ctx, msgID, ts, node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay message: %w", err)
	}
	return resp, nil
}

// SendRelayGroupMessage sends a pre-encrypted group message using sender keys.
//
// This compatibility wrapper sends only the top-level sender-key ciphertext and no per-device
// SKDM fanout. Use SendRelayMultiDeviceGroupMessage for a complete group send.
func (cli *Client) SendRelayGroupMessage(
	ctx context.Context,
	groupJID types.JID,
	preEncryptedPayload []byte,
	opts RelayMessageOptions,
	phash string,
) (*RelayMessageResponse, error) {
	return cli.SendRelayMultiDeviceGroupMessage(ctx, groupJID, nil, preEncryptedPayload, opts, phash)
}

// SendRelayMultiDeviceGroupMessage sends a group message with explicit per-device participant fanout.
//
// The participant messages are the sender-key distribution messages encrypted 1:1 for each
// target device, and senderKeyPayload is the top-level skmsg payload for the group.
func (cli *Client) SendRelayMultiDeviceGroupMessage(
	ctx context.Context,
	groupJID types.JID,
	participants []RelayParticipantMessage,
	senderKeyPayload []byte,
	opts RelayMessageOptions,
	phash string,
) (*RelayMessageResponse, error) {
	if groupJID.IsEmpty() {
		return nil, fmt.Errorf("group JID is required")
	}
	if len(senderKeyPayload) == 0 {
		return nil, fmt.Errorf("sender key payload cannot be empty")
	}
	opts.EncryptionType = RelayEncryptionSenderKey

	msgID, ts, msgType := cli.normalizeRelayMessageOptions(&opts)
	node, err := cli.buildRelayGroupMessageNode(groupJID, participants, senderKeyPayload, opts, msgID, msgType, phash)
	if err != nil {
		return nil, err
	}

	resp, err := cli.sendRelayNodeAndWait(ctx, msgID, ts, node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay group message: %w", err)
	}
	return resp, nil
}

// SendRelayRetryMessage sends a client-built retry replay payload using the original retry envelope metadata.
func (cli *Client) SendRelayRetryMessage(
	ctx context.Context,
	to types.JID,
	preEncryptedPayload []byte,
	opts RelayRetryMessageOptions,
) (*RelayMessageResponse, error) {
	if to.IsEmpty() {
		return nil, fmt.Errorf("retry target JID is required")
	}
	if len(preEncryptedPayload) == 0 {
		return nil, fmt.Errorf("retry payload cannot be empty")
	}
	if err := validateRelayEncryptionType(opts.EncryptionType); err != nil {
		return nil, err
	}
	if opts.MessageID == "" {
		return nil, fmt.Errorf("retry message id is required")
	}
	if opts.RetryCount <= 0 {
		return nil, fmt.Errorf("retry count must be greater than zero")
	}

	msgType := opts.MessageType
	if msgType == "" {
		msgType = "text"
	}
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	node := cli.buildRelayRetryMessageNode(to, preEncryptedPayload, opts, msgType, ts)
	resp, err := cli.sendRelayNodeAndWait(ctx, opts.MessageID, ts, node)
	if err != nil {
		return nil, fmt.Errorf("failed to send relay retry message: %w", err)
	}
	return resp, nil
}

func (cli *Client) normalizeRelayMessageOptions(opts *RelayMessageOptions) (types.MessageID, time.Time, string) {
	msgID := opts.MessageID
	if msgID == "" {
		msgID = cli.GenerateMessageID()
	}
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	msgType := opts.MessageType
	if msgType == "" {
		msgType = "text"
	}
	return msgID, ts, msgType
}

func validateRelayEncryptionType(encType RelayEncryptionType) error {
	switch encType {
	case RelayEncryptionPreKey, RelayEncryptionNormal, RelayEncryptionSenderKey:
		return nil
	case "":
		return fmt.Errorf("encryption type is required")
	default:
		return fmt.Errorf("invalid encryption type: %s (must be pkmsg, msg, or skmsg)", encType)
	}
}

func validateRelayParticipants(participants []RelayParticipantMessage) error {
	for i, participant := range participants {
		if participant.JID.IsEmpty() {
			return fmt.Errorf("relay participant %d has empty JID", i)
		}
		if len(participant.Payload) == 0 {
			return fmt.Errorf("relay participant %d has empty payload", i)
		}
		if err := validateRelayEncryptionType(participant.EncryptionType); err != nil {
			return fmt.Errorf("relay participant %d: %w", i, err)
		}
	}
	return nil
}

// buildRelayMessageNode constructs a message binary node with pre-encrypted per-device content.
func (cli *Client) buildRelayMessageNode(
	to types.JID,
	participants []RelayParticipantMessage,
	opts RelayMessageOptions,
	msgID types.MessageID,
	msgType string,
) (*waBinary.Node, error) {
	if err := validateRelayParticipants(participants); err != nil {
		return nil, err
	}
	participantNode, includeIdentity := cli.buildRelayParticipantsNode(participants)
	content := []waBinary.Node{participantNode}
	if opts.IncludeDeviceIdentity || includeIdentity {
		content = append(content, cli.makeDeviceIdentityNode())
	}
	content = append(content, opts.AdditionalNodes...)

	return &waBinary.Node{
		Tag: "message",
		Attrs: waBinary.Attrs{
			"id":   msgID,
			"type": msgType,
			"to":   to,
		},
		Content: content,
	}, nil
}

// buildRelayGroupMessageNode constructs a group message node with sender-key payload and optional per-device SKDM fanout.
func (cli *Client) buildRelayGroupMessageNode(
	groupJID types.JID,
	participants []RelayParticipantMessage,
	senderKeyPayload []byte,
	opts RelayMessageOptions,
	msgID types.MessageID,
	msgType string,
	phash string,
) (*waBinary.Node, error) {
	content := make([]waBinary.Node, 0, 2+len(opts.AdditionalNodes))
	includeIdentity := false
	if len(participants) > 0 {
		if err := validateRelayParticipants(participants); err != nil {
			return nil, err
		}
		participantNode, participantIdentity := cli.buildRelayParticipantsNode(participants)
		content = append(content, participantNode)
		includeIdentity = participantIdentity
	}
	if opts.IncludeDeviceIdentity || includeIdentity {
		content = append(content, cli.makeDeviceIdentityNode())
	}
	content = append(content, waBinary.Node{
		Tag:     "enc",
		Attrs:   relayEncAttrs(RelayEncryptionSenderKey, opts.MediaType),
		Content: senderKeyPayload,
	})
	content = append(content, opts.AdditionalNodes...)

	attrs := waBinary.Attrs{
		"id":   msgID,
		"type": msgType,
		"to":   groupJID,
	}
	if phash != "" {
		attrs["phash"] = phash
	}
	return &waBinary.Node{
		Tag:     "message",
		Attrs:   attrs,
		Content: content,
	}, nil
}

func (cli *Client) buildRelayRetryMessageNode(
	to types.JID,
	preEncryptedPayload []byte,
	opts RelayRetryMessageOptions,
	msgType string,
	ts time.Time,
) *waBinary.Node {
	content := []waBinary.Node{{
		Tag:     "enc",
		Attrs:   relayEncAttrs(opts.EncryptionType, opts.MediaType),
		Content: preEncryptedPayload,
	}}
	if opts.IncludeDeviceIdentity || opts.EncryptionType == RelayEncryptionPreKey {
		content = append(content, cli.makeDeviceIdentityNode())
	}

	attrs := waBinary.Attrs{
		"to":   to,
		"type": msgType,
		"id":   opts.MessageID,
		"t":    ts.Unix(),
	}
	if !opts.IsGroup {
		attrs["device_fanout"] = false
	}
	if !opts.Participant.IsEmpty() {
		attrs["participant"] = opts.Participant
	}
	if !opts.Recipient.IsEmpty() {
		attrs["recipient"] = opts.Recipient
	}
	if opts.Edit != "" {
		attrs["edit"] = opts.Edit
	}

	content[0].Attrs["count"] = opts.RetryCount
	return &waBinary.Node{
		Tag:     "message",
		Attrs:   attrs,
		Content: content,
	}
}

func relayEncAttrs(encType RelayEncryptionType, mediaType string) waBinary.Attrs {
	attrs := waBinary.Attrs{
		"v":    "2",
		"type": string(encType),
	}
	if mediaType != "" {
		attrs["mediatype"] = mediaType
	}
	return attrs
}

func (cli *Client) buildRelayParticipantsNode(participants []RelayParticipantMessage) (waBinary.Node, bool) {
	nodes := make([]waBinary.Node, 0, len(participants))
	includeIdentity := false
	for _, participant := range participants {
		encNode := waBinary.Node{
			Tag:     "enc",
			Attrs:   relayEncAttrs(participant.EncryptionType, participant.MediaType),
			Content: participant.Payload,
		}
		nodes = append(nodes, waBinary.Node{
			Tag:     "to",
			Attrs:   waBinary.Attrs{"jid": participant.JID},
			Content: []waBinary.Node{encNode},
		})
		if participant.EncryptionType == RelayEncryptionPreKey {
			includeIdentity = true
		}
	}
	return waBinary.Node{
		Tag:     "participants",
		Content: nodes,
	}, includeIdentity
}

func (cli *Client) sendRelayNodeAndWait(
	ctx context.Context,
	msgID types.MessageID,
	fallbackTimestamp time.Time,
	node *waBinary.Node,
) (*RelayMessageResponse, error) {
	respChan := cli.waitResponse(string(msgID))
	data, err := cli.sendNodeAndGetData(ctx, *node)
	if err != nil {
		cli.cancelResponse(string(msgID), respChan)
		return nil, err
	}

	var respNode *waBinary.Node
	select {
	case respNode = <-respChan:
	case <-ctx.Done():
		cli.cancelResponse(string(msgID), respChan)
		return nil, ctx.Err()
	}
	if isDisconnectNode(respNode) {
		respNode, err = cli.retryFrame(ctx, "relay message send", string(msgID), data, respNode, 0)
		if err != nil {
			return nil, err
		}
	}

	ag := respNode.AttrGetter()
	resp := &RelayMessageResponse{
		ID:              msgID,
		Timestamp:       ag.UnixTime("t"),
		ServerID:        types.MessageServerID(ag.OptionalInt("server_id")),
		ParticipantHash: ag.OptionalString("phash"),
		SentNode:        data,
	}
	if resp.Timestamp.IsZero() {
		resp.Timestamp = fallbackTimestamp
	}
	resp.ServerData, _ = waBinary.Marshal(*respNode)
	if errorCode := ag.Int("error"); errorCode != 0 {
		return resp, fmt.Errorf("%w %d", ErrServerReturnedError, errorCode)
	}
	return resp, nil
}
