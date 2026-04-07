package whatsmeow

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/libsignal/ecc"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

type relayPairSuccessFixture struct {
	pairSuccessPayload   []byte
	pairSuccessResponse  *RelayPairSuccessResponse
	companionIdentityKey *keys.KeyPair
	advSecret            []byte
}

type recordingDeviceContainer struct {
	putCalls int
}

func (r *recordingDeviceContainer) PutDevice(ctx context.Context, device *store.Device) error {
	r.putCalls++
	return nil
}

func (r *recordingDeviceContainer) DeleteDevice(ctx context.Context, device *store.Device) error {
	return nil
}

type recordingLIDStore struct {
	putCalls int
}

func (r *recordingLIDStore) PutManyLIDMappings(ctx context.Context, mappings []store.LIDMapping) error {
	r.putCalls += len(mappings)
	return nil
}

func (r *recordingLIDStore) PutLIDMapping(ctx context.Context, lid, jid types.JID) error {
	r.putCalls++
	return nil
}

func (r *recordingLIDStore) GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error) {
	return types.EmptyJID, nil
}

func (r *recordingLIDStore) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	return types.EmptyJID, nil
}

func (r *recordingLIDStore) GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error) {
	return map[types.JID]types.JID{}, nil
}

func buildRelayPairSuccessFixture(t *testing.T) relayPairSuccessFixture {
	t.Helper()

	companionSeed := [32]byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	}
	companionIdentity := companionX25519KeyPairFromEd25519Seed(companionSeed)
	primaryIdentity := keys.NewKeyPair()
	advSecret := []byte("0123456789abcdef0123456789abcdef")

	deviceDetails := &waAdv.ADVDeviceIdentity{
		KeyIndex:    proto.Uint32(42),
		AccountType: waAdv.ADVEncryptionType_E2EE.Enum(),
		DeviceType:  waAdv.ADVEncryptionType_E2EE.Enum(),
	}
	deviceDetailsBytes, err := proto.Marshal(deviceDetails)
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}

	accountMessage := concatBytes(AdvAccountSignaturePrefix, deviceDetailsBytes, companionIdentity.Pub[:])
	accountSignature := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*primaryIdentity.Priv), accountMessage)

	originalIdentity := &waAdv.ADVSignedDeviceIdentity{
		Details:             deviceDetailsBytes,
		AccountSignatureKey: primaryIdentity.Pub[:],
		AccountSignature:    accountSignature[:],
	}
	originalIdentityBytes, err := proto.Marshal(originalIdentity)
	if err != nil {
		t.Fatalf("marshal original identity: %v", err)
	}

	mac := hmac.New(sha256.New, advSecret)
	mac.Write(originalIdentityBytes)
	pairSuccessPayload, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentityHMAC{
		Details:     originalIdentityBytes,
		HMAC:        mac.Sum(nil),
		AccountType: waAdv.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		t.Fatalf("marshal pair success payload: %v", err)
	}

	deviceMessage := concatBytes(AdvDeviceSignaturePrefix, deviceDetailsBytes, companionIdentity.Pub[:], primaryIdentity.Pub[:])
	deviceSignature := signWithEd25519SeedAndEmbeddedSignBit(companionSeed, deviceMessage)

	accountIdentity := &waAdv.ADVSignedDeviceIdentity{
		Details:             deviceDetailsBytes,
		AccountSignatureKey: primaryIdentity.Pub[:],
		AccountSignature:    accountSignature[:],
		DeviceSignature:     deviceSignature[:],
	}
	accountIdentityBytes, err := proto.Marshal(accountIdentity)
	if err != nil {
		t.Fatalf("marshal account identity: %v", err)
	}

	selfSignedIdentity := &waAdv.ADVSignedDeviceIdentity{
		Details:          deviceDetailsBytes,
		AccountSignature: accountSignature[:],
		DeviceSignature:  deviceSignature[:],
	}
	selfSignedIdentityBytes, err := proto.Marshal(selfSignedIdentity)
	if err != nil {
		t.Fatalf("marshal self-signed identity: %v", err)
	}

	return relayPairSuccessFixture{
		pairSuccessPayload: pairSuccessPayload,
		pairSuccessResponse: &RelayPairSuccessResponse{
			Account:        accountIdentityBytes,
			DeviceIdentity: selfSignedIdentityBytes,
			KeyIndex:       42,
		},
		companionIdentityKey: companionIdentity,
		advSecret:            advSecret,
	}
}

func TestValidateRelayPairSuccessResponseAcceptsClientBuiltResponse(t *testing.T) {
	fixture := buildRelayPairSuccessFixture(t)
	cli := NewClient(&store.Device{
		IdentityKey:  fixture.companionIdentityKey,
		AdvSecretKey: fixture.advSecret,
	}, nil)

	parsedOriginalIdentity, parsedDetails, err := cli.parseAndValidatePairSuccess(context.Background(), fixture.pairSuccessPayload, "req-1")
	if err != nil {
		t.Fatalf("parseAndValidatePairSuccess returned error: %v", err)
	}

	account, err := cli.validateRelayPairSuccessResponse(fixture.pairSuccessResponse, parsedOriginalIdentity, parsedDetails)
	if err != nil {
		t.Fatalf("validateRelayPairSuccessResponse returned error: %v", err)
	}
	if len(account.GetDeviceSignature()) != 64 {
		t.Fatalf("expected persisted relay account to contain device signature, got %d bytes", len(account.GetDeviceSignature()))
	}
}

func TestHandleRelayPairFailsWhenRelayKeyApplyCallbackFails(t *testing.T) {
	fixture := buildRelayPairSuccessFixture(t)
	container := &recordingDeviceContainer{}
	lidStore := &recordingLIDStore{}
	jid := types.NewJID("15551234567", types.DefaultUserServer)
	lid := types.NewJID("15551234567", types.HiddenUserServer)
	callbackErr := errors.New("relay key apply failed")

	cli := NewClient(&store.Device{
		Container:    container,
		LIDs:         lidStore,
		IdentityKey:  fixture.companionIdentityKey,
		AdvSecretKey: fixture.advSecret,
	}, nil)
	cli.RelayPairSuccessCallback = func(ctx context.Context, request *RelayPairSuccessRequest) (*RelayPairSuccessResponse, error) {
		return fixture.pairSuccessResponse, nil
	}
	cli.RelayKeyApplyCallback = func(device *store.Device) error {
		return callbackErr
	}

	err := cli.handleRelayPair(context.Background(), fixture.pairSuccessPayload, "req-1", "Test Business", "ios", jid, lid)
	if err == nil {
		t.Fatal("expected relay pair to fail when RelayKeyApplyCallback fails")
	}
	var dbErr *PairDatabaseError
	if !errors.As(err, &dbErr) {
		t.Fatalf("expected PairDatabaseError, got %T: %v", err, err)
	}
	if !errors.Is(err, callbackErr) {
		t.Fatalf("expected relay key apply error to be wrapped, got %v", err)
	}
	if container.putCalls != 0 {
		t.Fatalf("expected relay pair to abort before saving the device, got %d save call(s)", container.putCalls)
	}
	if lidStore.putCalls != 0 {
		t.Fatalf("expected relay pair to abort before storing LID mappings, got %d put call(s)", lidStore.putCalls)
	}
}

func companionX25519KeyPairFromEd25519Seed(seed [32]byte) *keys.KeyPair {
	hash := sha512.Sum512(seed[:])
	var priv [32]byte
	copy(priv[:], hash[:32])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	return keys.NewKeyPairFromPrivateKey(priv)
}

func signWithEd25519SeedAndEmbeddedSignBit(seed [32]byte, message []byte) [64]byte {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, message)
	signature[63] = (signature[63] & 0x7f) | (publicKey[31] & 0x80)

	return *(*[64]byte)(signature)
}

func TestVerifyDeviceSignatureWithAccountKeyAcceptsEd25519SeedSignature(t *testing.T) {
	seed := [32]byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
	}
	companionIdentity := companionX25519KeyPairFromEd25519Seed(seed)
	accountKey := keys.NewKeyPair()

	message := concatBytes(AdvDeviceSignaturePrefix, []byte("details"), companionIdentity.Pub[:], accountKey.Pub[:])
	signature := signWithEd25519SeedAndEmbeddedSignBit(seed, message)

	deviceIdentity := &waAdv.ADVSignedDeviceIdentity{
		Details:         []byte("details"),
		DeviceSignature: signature[:],
	}
	if !verifyDeviceSignatureWithAccountKey(deviceIdentity, companionIdentity, accountKey.Pub[:]) {
		t.Fatal("expected Go verifier to accept client-built Ed25519 signature with embedded sign bit")
	}
}
