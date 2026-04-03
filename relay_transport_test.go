package whatsmeow

import (
	"context"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

func TestValidateRelayTransportConfigurationRequiresSKDMCallback(t *testing.T) {
	var identityPub [32]byte
	var signedPreKeyPub [32]byte
	var signedPreKeySig [64]byte
	device := &store.Device{
		TransportOnly: true,
		IdentityKey:   &keys.KeyPair{Pub: &identityPub},
		SignedPreKey:  &keys.PreKey{KeyID: 7, KeyPair: keys.KeyPair{Pub: &signedPreKeyPub}, Signature: &signedPreKeySig},
	}

	cli := NewClient(device, nil)
	cli.SetRelayTransportMode(true)
	cli.RelayMessageCallback = func(ctx context.Context, info *types.MessageInfo, node *waBinary.Node) bool { return true }
	cli.RelayNotificationCallback = func(ctx context.Context, node *waBinary.Node) (bool, error) { return true, nil }
	cli.RelayRetryReceiptCallback = func(ctx context.Context, receipt *events.Receipt, retryCount int, node *waBinary.Node) {}

	err := cli.validateRelayTransportConfiguration()
	if err != ErrNoADVSecret {
		t.Fatalf("expected adv secret requirement before login, got %v", err)
	}

	device.AdvSecretKey = make([]byte, 32)
	err = cli.validateRelayTransportConfiguration()
	if err != ErrRelayTransportRequiresPairSuccessCallback {
		t.Fatalf("expected pair-success callback error before login after adv secret configured, got %v", err)
	}

	jid := types.NewJID("15551234567", types.DefaultUserServer)
	device.ID = &jid
	err = cli.validateRelayTransportConfiguration()
	if err != ErrRelayTransportRequiresSKDMCallback {
		t.Fatalf("expected SKDM callback requirement, got %v", err)
	}
}

func TestValidateRelayTransportConfigurationAllowsLinkedReconnectWithoutBootstrapKeys(t *testing.T) {
	jid := types.NewJID("15551234567", types.DefaultUserServer)
	device := &store.Device{
		TransportOnly: true,
		ID:            &jid,
	}

	cli := NewClient(device, nil)
	cli.SetRelayTransportMode(true)
	cli.RelayMessageCallback = func(ctx context.Context, info *types.MessageInfo, node *waBinary.Node) bool { return true }
	cli.RelayNotificationCallback = func(ctx context.Context, node *waBinary.Node) (bool, error) { return true, nil }
	cli.RelayRetryReceiptCallback = func(ctx context.Context, receipt *events.Receipt, retryCount int, node *waBinary.Node) {}
	cli.RelaySkdmCallback = func(ctx context.Context, groupJid types.JID, senderJid types.JID, skdmBytes []byte) {}

	if err := cli.validateRelayTransportConfiguration(); err != nil {
		t.Fatalf("expected linked transport-only reconnect without stored bootstrap keys to validate, got %v", err)
	}
}

func TestAllowRelayTransportNotificationFallback(t *testing.T) {
	for _, notifType := range []string{"disappearing_mode", "mex", "picture", "status"} {
		if !allowRelayTransportNotificationFallback(notifType) {
			t.Fatalf("expected %s notifications to allow safe relay fallback", notifType)
		}
	}
	if allowRelayTransportNotificationFallback("devices") {
		t.Fatalf("did not expect devices notifications to allow relay fallback")
	}
}
