package whatsmeow

import (
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func TestParseGroupNodeParsesModernMetadataFields(t *testing.T) {
	cli := &Client{}
	groupNode := &waBinary.Node{
		Tag: "group",
		Attrs: waBinary.Attrs{
			"id":              "120363400000000000",
			"creation":        "1700000000",
			"subject":         "Relay Test Group",
			"creator":         types.NewJID("15551234567", types.HiddenUserServer),
			"creator_pn":      types.NewJID("15551234567", types.DefaultUserServer),
			"addressing_mode": "lid",
		},
		Content: []waBinary.Node{
			{Tag: "member_add_mode", Content: []byte("admin_add")},
			{Tag: "member_link_mode", Content: []byte("all_member_link")},
			{Tag: "member_share_group_history_mode", Content: []byte("all_member_share")},
			{Tag: "allow_non_admin_sub_group_creation"},
			{Tag: "hidden_group"},
			{Tag: "limit_sharing_enabled"},
			{Tag: "general_chat"},
		},
	}

	info, err := cli.parseGroupNode(groupNode)
	if err != nil {
		t.Fatalf("parseGroupNode returned error: %v", err)
	}
	if info.MemberAddMode != types.GroupMemberAddModeAdmin {
		t.Fatalf("unexpected member add mode: %q", info.MemberAddMode)
	}
	if info.MemberLinkMode != types.GroupMemberLinkModeAllMember {
		t.Fatalf("unexpected member link mode: %q", info.MemberLinkMode)
	}
	if info.MemberShareGroupHistoryMode != types.GroupMemberShareGroupHistoryModeAllMember {
		t.Fatalf("unexpected group history sharing mode: %q", info.MemberShareGroupHistoryMode)
	}
	if !info.AllowNonAdminSubGroupCreation {
		t.Fatal("expected allow_non_admin_sub_group_creation to be true")
	}
	if !info.IsHiddenGroup {
		t.Fatal("expected hidden_group to be true")
	}
	if !info.IsLimitSharingEnabled {
		t.Fatal("expected limit_sharing_enabled to be true")
	}
	if !info.IsGeneralChat {
		t.Fatal("expected general_chat to be true")
	}
}

func TestParseGroupChangeParsesModernMetadataFields(t *testing.T) {
	cli := &Client{}
	changeNode := &waBinary.Node{
		Tag: "notification",
		Attrs: waBinary.Attrs{
			"from": types.NewJID("120363400000000000", types.GroupServer),
			"t":    "1700000001",
		},
		Content: []waBinary.Node{
			{Tag: "member_link_mode", Content: []byte("admin_link")},
			{Tag: "member_share_group_history_mode", Content: []byte("all_member_share")},
			{Tag: "allow_non_admin_sub_group_creation"},
			{Tag: "hidden_group"},
			{Tag: "limit_sharing_enabled"},
			{Tag: "general_chat"},
		},
	}

	evt, _, err := cli.parseGroupChange(changeNode)
	if err != nil {
		t.Fatalf("parseGroupChange returned error: %v", err)
	}
	if evt.MemberLinkMode == nil || *evt.MemberLinkMode != types.GroupMemberLinkModeAdmin {
		t.Fatalf("unexpected member link mode: %+v", evt.MemberLinkMode)
	}
	if evt.MemberShareGroupHistoryMode == nil || *evt.MemberShareGroupHistoryMode != types.GroupMemberShareGroupHistoryModeAllMember {
		t.Fatalf("unexpected group history sharing mode: %+v", evt.MemberShareGroupHistoryMode)
	}
	if evt.AllowNonAdminSubGroupCreation == nil || !*evt.AllowNonAdminSubGroupCreation {
		t.Fatalf("unexpected allow_non_admin_sub_group_creation value: %+v", evt.AllowNonAdminSubGroupCreation)
	}
	if evt.HiddenGroup == nil || !evt.HiddenGroup.IsHiddenGroup {
		t.Fatalf("unexpected hidden_group value: %+v", evt.HiddenGroup)
	}
	if evt.LimitSharing == nil || !evt.LimitSharing.IsLimitSharingEnabled {
		t.Fatalf("unexpected limit_sharing_enabled value: %+v", evt.LimitSharing)
	}
	if evt.GeneralChat == nil || !evt.GeneralChat.IsGeneralChat {
		t.Fatalf("unexpected general_chat value: %+v", evt.GeneralChat)
	}
}
