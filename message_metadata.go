// Copyright (c) 2024 Pally Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"strings"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type messageAttrs struct {
	Type              string
	MediaType         string
	Edit              types.EditAttribute
	DecryptFail       events.DecryptFailMode
	PollType          string
	ButtonType        string
	ButtonAttributes  waBinary.Attrs
	ExtraMessageAttrs waBinary.Attrs
}

// MessageNodeMetadata describes the canonical WhatsApp binary node metadata for a waE2E.Message.
//
// In relay mode, build this metadata in the component that still owns the plaintext protobuf
// message, then pass only the metadata alongside the encrypted payload to the transport-only relay.
type MessageNodeMetadata struct {
	Type              string
	MediaType         string
	Edit              types.EditAttribute
	DecryptFail       events.DecryptFailMode
	PollType          string
	ButtonType        string
	ButtonAttributes  waBinary.Attrs
	ExtraMessageAttrs waBinary.Attrs
}

type MessageNodeMetadataOptions struct {
	Peer bool
}

// BuildMessageNodeMetadata derives the canonical outer-node metadata that whatsmeow uses for the
// given protobuf message.
func BuildMessageNodeMetadata(message *waE2E.Message, opts MessageNodeMetadataOptions) MessageNodeMetadata {
	if message == nil {
		if opts.Peer {
			return MessageNodeMetadata{Type: "text"}
		}
		return MessageNodeMetadata{Type: "text"}
	}

	attrs := getAttrsFromMessage(message)
	metadata := MessageNodeMetadata{
		Type:              attrs.Type,
		MediaType:         attrs.MediaType,
		Edit:              attrs.Edit,
		DecryptFail:       attrs.DecryptFail,
		PollType:          attrs.PollType,
		ButtonType:        attrs.ButtonType,
		ButtonAttributes:  cloneAttrs(attrs.ButtonAttributes),
		ExtraMessageAttrs: cloneAttrs(attrs.ExtraMessageAttrs),
	}
	if opts.Peer {
		metadata.Type = "text"
		metadata.ExtraMessageAttrs = cloneAttrs(peerMessageExtraAttrs(message))
	}
	if metadata.Type == "" {
		metadata.Type = "text"
	}
	return metadata
}

func cloneAttrs(attrs waBinary.Attrs) waBinary.Attrs {
	if len(attrs) == 0 {
		return nil
	}
	cloned := make(waBinary.Attrs, len(attrs))
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}

func mergeAttrs(dst, src waBinary.Attrs) waBinary.Attrs {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = waBinary.Attrs{}
	}
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func applyMessageNodeMetadata(attrs waBinary.Attrs, metadata MessageNodeMetadata) waBinary.Attrs {
	attrs["type"] = metadata.Type
	if metadata.Edit != "" {
		attrs["edit"] = string(metadata.Edit)
	}
	return mergeAttrs(attrs, metadata.ExtraMessageAttrs)
}

func appendMessageMetadataNodes(content []waBinary.Node, metadata MessageNodeMetadata, additionalNodes []waBinary.Node) []waBinary.Node {
	if metadata.PollType != "" {
		content = append(content, waBinary.Node{
			Tag: "meta",
			Attrs: waBinary.Attrs{
				"polltype": metadata.PollType,
			},
		})
	}
	if len(additionalNodes) > 0 {
		content = append(content, additionalNodes...)
	}
	if metadata.ButtonType != "" {
		content = append(content, waBinary.Node{
			Tag: "biz",
			Content: []waBinary.Node{{
				Tag:   metadata.ButtonType,
				Attrs: cloneAttrs(metadata.ButtonAttributes),
			}},
		})
	}
	return content
}

func getAttrsFromMessage(msg *waE2E.Message) (attrs messageAttrs) {
	attrs.Type = getTypeFromMessage(msg)
	attrs.MediaType = getMediaTypeFromMessage(msg)
	attrs.Edit = getEditAttribute(msg)
	if attrs.Type == "poll" {
		attrs.PollType = "creation"
		if msg.GetPollUpdateMessage() != nil {
			attrs.PollType = "vote"
		}
	}
	if attrs.Edit != "" || attrs.Type == "reaction" || msg.GetPollUpdateMessage() != nil {
		attrs.DecryptFail = events.DecryptFailHide
	}
	if buttonType := getButtonTypeFromMessage(msg); buttonType != "" {
		attrs.ButtonType = buttonType
		attrs.ButtonAttributes = getButtonAttributes(msg)
	}
	if attrs.Type == "" {
		attrs.Type = "text"
	}
	return
}

func peerMessageExtraAttrs(message *waE2E.Message) waBinary.Attrs {
	attrs := waBinary.Attrs{}
	protoMsg := message.GetProtocolMessage()
	if protoMsg.GetType() == waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST {
		attrs["push_priority"] = "high"
	} else if protoMsg.GetPeerDataOperationRequestMessage().GetPeerDataOperationRequestType() == waE2E.PeerDataOperationRequestType_HISTORY_SYNC_ON_DEMAND {
		attrs["privacy_sensitive"] = "1"
	}
	return attrs
}

func getTypeFromMessage(msg *waE2E.Message) string {
	if msg == nil {
		return "text"
	}
	switch {
	case msg.ViewOnceMessage != nil:
		return getTypeFromMessage(msg.ViewOnceMessage.Message)
	case msg.ViewOnceMessageV2 != nil:
		return getTypeFromMessage(msg.ViewOnceMessageV2.Message)
	case msg.ViewOnceMessageV2Extension != nil:
		return getTypeFromMessage(msg.ViewOnceMessageV2Extension.Message)
	case msg.LottieStickerMessage != nil:
		return getTypeFromMessage(msg.LottieStickerMessage.Message)
	case msg.EphemeralMessage != nil:
		return getTypeFromMessage(msg.EphemeralMessage.Message)
	case msg.DocumentWithCaptionMessage != nil:
		return getTypeFromMessage(msg.DocumentWithCaptionMessage.Message)
	case msg.ReactionMessage != nil, msg.EncReactionMessage != nil:
		return "reaction"
	case msg.PollCreationMessage != nil, msg.PollUpdateMessage != nil:
		return "poll"
	case getMediaTypeFromMessage(msg) != "":
		return "media"
	case msg.Conversation != nil, msg.ExtendedTextMessage != nil, msg.ProtocolMessage != nil:
		return "text"
	default:
		return "text"
	}
}

func getMediaTypeFromMessage(msg *waE2E.Message) string {
	if msg == nil {
		return ""
	}
	switch {
	case msg.ViewOnceMessage != nil:
		return getMediaTypeFromMessage(msg.ViewOnceMessage.Message)
	case msg.ViewOnceMessageV2 != nil:
		return getMediaTypeFromMessage(msg.ViewOnceMessageV2.Message)
	case msg.ViewOnceMessageV2Extension != nil:
		return getMediaTypeFromMessage(msg.ViewOnceMessageV2Extension.Message)
	case msg.LottieStickerMessage != nil:
		return getMediaTypeFromMessage(msg.LottieStickerMessage.Message)
	case msg.EphemeralMessage != nil:
		return getMediaTypeFromMessage(msg.EphemeralMessage.Message)
	case msg.DocumentWithCaptionMessage != nil:
		return getMediaTypeFromMessage(msg.DocumentWithCaptionMessage.Message)
	case msg.ExtendedTextMessage != nil && msg.ExtendedTextMessage.Title != nil:
		return "url"
	case msg.ImageMessage != nil:
		return "image"
	case msg.StickerMessage != nil:
		return "sticker"
	case msg.DocumentMessage != nil:
		return "document"
	case msg.AudioMessage != nil:
		if msg.AudioMessage.GetPTT() {
			return "ptt"
		}
		return "audio"
	case msg.VideoMessage != nil:
		if msg.VideoMessage.GetGifPlayback() {
			return "gif"
		}
		return "video"
	case msg.ContactMessage != nil:
		return "vcard"
	case msg.ContactsArrayMessage != nil:
		return "contact_array"
	case msg.LocationMessage != nil, msg.LiveLocationMessage != nil:
		return "location"
	case msg.ListMessage != nil:
		return "list"
	case msg.ListResponseMessage != nil:
		return "list_response"
	case msg.ButtonsResponseMessage != nil:
		return "buttons_response"
	case msg.OrderMessage != nil:
		return "order"
	case msg.ProductMessage != nil:
		return "product"
	case msg.InteractiveResponseMessage != nil:
		return "native_flow_response"
	default:
		return ""
	}
}

func getButtonTypeFromMessage(msg *waE2E.Message) string {
	if msg == nil {
		return ""
	}
	switch {
	case msg.ViewOnceMessage != nil:
		return getButtonTypeFromMessage(msg.ViewOnceMessage.Message)
	case msg.ViewOnceMessageV2 != nil:
		return getButtonTypeFromMessage(msg.ViewOnceMessageV2.Message)
	case msg.EphemeralMessage != nil:
		return getButtonTypeFromMessage(msg.EphemeralMessage.Message)
	case msg.ButtonsMessage != nil:
		return "buttons"
	case msg.ButtonsResponseMessage != nil:
		return "buttons_response"
	case msg.ListMessage != nil:
		return "list"
	case msg.ListResponseMessage != nil:
		return "list_response"
	case msg.InteractiveResponseMessage != nil:
		return "interactive_response"
	default:
		return ""
	}
}

func getButtonAttributes(msg *waE2E.Message) waBinary.Attrs {
	if msg == nil {
		return nil
	}
	switch {
	case msg.ViewOnceMessage != nil:
		return getButtonAttributes(msg.ViewOnceMessage.Message)
	case msg.ViewOnceMessageV2 != nil:
		return getButtonAttributes(msg.ViewOnceMessageV2.Message)
	case msg.EphemeralMessage != nil:
		return getButtonAttributes(msg.EphemeralMessage.Message)
	case msg.TemplateMessage != nil:
		return waBinary.Attrs{}
	case msg.ListMessage != nil:
		return waBinary.Attrs{
			"v":    "2",
			"type": strings.ToLower(waE2E.ListMessage_ListType_name[int32(msg.ListMessage.GetListType())]),
		}
	default:
		return nil
	}
}

const RemoveReactionText = ""

func getEditAttribute(msg *waE2E.Message) types.EditAttribute {
	if msg == nil {
		return types.EditAttributeEmpty
	}
	switch {
	case msg.EditedMessage != nil && msg.EditedMessage.Message != nil:
		return getEditAttribute(msg.EditedMessage.Message)
	case msg.ProtocolMessage != nil && msg.ProtocolMessage.GetKey() != nil:
		switch msg.ProtocolMessage.GetType() {
		case waE2E.ProtocolMessage_REVOKE:
			if msg.ProtocolMessage.GetKey().GetFromMe() {
				return types.EditAttributeSenderRevoke
			}
			return types.EditAttributeAdminRevoke
		case waE2E.ProtocolMessage_MESSAGE_EDIT:
			if msg.ProtocolMessage.EditedMessage != nil {
				return types.EditAttributeMessageEdit
			}
		}
	case msg.ReactionMessage != nil && msg.ReactionMessage.GetText() == RemoveReactionText:
		return types.EditAttributeSenderRevoke
	case msg.KeepInChatMessage != nil && msg.KeepInChatMessage.GetKey().GetFromMe() && msg.KeepInChatMessage.GetKeepType() == waE2E.KeepType_UNDO_KEEP_FOR_ALL:
		return types.EditAttributeSenderRevoke
	}
	return types.EditAttributeEmpty
}
