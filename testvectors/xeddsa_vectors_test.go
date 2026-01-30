package testvectors

// XEdDSA Test Vector Generator for iOS/Swift compatibility testing
//
// Run with: go test -v -run TestGenerateXEdDSAVectors
//
// This generates JSON test vectors that can be used to validate
// the iOS XEdDSA implementation against the Go reference.

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"go.mau.fi/libsignal/ecc"
	"golang.org/x/crypto/curve25519"
)

// TestVectorSet contains all test vectors for cross-platform validation
type TestVectorSet struct {
	Version              string                   `json:"version"`
	Description          string                   `json:"description"`
	KeyGeneration        []KeyGenerationVector    `json:"keyGeneration"`
	MongoToEdwards       []MongoToEdwardsVector   `json:"montgomeryToEdwards"`
	XEdDSASigning        []XEdDSASigningVector    `json:"xeddsaSigning"`
	SignedPreKey         []SignedPreKeyVector     `json:"signedPreKey"`
	DeviceSignature      []DeviceSignatureVector  `json:"deviceSignature"`
}

type KeyGenerationVector struct {
	Description       string `json:"description"`
	Seed              string `json:"seed"`
	ClampedPrivateKey string `json:"clampedPrivateKey"`
	PublicKey         string `json:"publicKey"`
}

type MongoToEdwardsVector struct {
	Description string `json:"description"`
	MontgomeryX string `json:"montgomeryX"`
	EdwardsY    string `json:"edwardsY"`
	Note        string `json:"note,omitempty"`
}

type XEdDSASigningVector struct {
	Description   string `json:"description"`
	PrivateKey    string `json:"privateKey"`
	PublicKey     string `json:"publicKey"`
	Message       string `json:"message"`
	MessageHex    string `json:"messageHex"`
	SignBit       int    `json:"signBit"`
	SignatureHex  string `json:"signatureHex"`
}

type SignedPreKeyVector struct {
	Description         string `json:"description"`
	IdentityPrivateKey  string `json:"identityPrivateKey"`
	IdentityPublicKey   string `json:"identityPublicKey"`
	PreKeyPublicKey     string `json:"preKeyPublicKey"`
	MessageToSign       string `json:"messageToSign"`
	SignatureHex        string `json:"signatureHex"`
}

type DeviceSignatureVector struct {
	Description       string `json:"description"`
	IdentityPrivKey   string `json:"identityPrivateKey"`
	IdentityPubKey    string `json:"identityPublicKey"`
	DeviceDetails     string `json:"deviceDetails"`
	AccountSigKey     string `json:"accountSignatureKey"`
	Prefix            []int  `json:"prefix"`
	MessageToSign     string `json:"messageToSign"`
	SignatureHex      string `json:"signatureHex"`
}

// clampPrivateKey applies X25519 clamping to a private key
func clampPrivateKey(priv *[32]byte) {
	priv[0] &= 248     // Clear bits 0-2
	priv[31] &= 127    // Clear bit 255
	priv[31] |= 64     // Set bit 254
}

// computePublicKey computes the Curve25519 public key
func computePublicKey(priv *[32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, priv)
	return pub
}

// montgomeryToEdwards converts Montgomery X to Edwards Y
func montgomeryToEdwards(montX [32]byte) [32]byte {
	var edY, one, montXElem, montXMinusOne, montXPlusOne field.Element
	montXElem.SetBytes(montX[:])
	one.One()
	montXMinusOne.Subtract(&montXElem, &one)
	montXPlusOne.Add(&montXElem, &one)
	montXPlusOne.Invert(&montXPlusOne)
	edY.Multiply(&montXMinusOne, &montXPlusOne)
	return *(*[32]byte)(edY.Bytes())
}

// signWithKnownRandom signs using XEdDSA with controllable random for deterministic output
func signWithKnownRandom(privateKey *[32]byte, message []byte, random [64]byte) [64]byte {
	// Calculate Ed25519 public key from Curve25519 private key
	var A edwards25519.Point
	privateKeyScalar, _ := edwards25519.NewScalar().SetBytesWithClamping(privateKey[:])
	A.ScalarBaseMult(privateKeyScalar)
	publicKey := *(*[32]byte)(A.Bytes())

	// Calculate r with diversifier
	diversifier := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}

	var r [64]byte
	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(privateKey[:])
	hash.Write(message)
	hash.Write(random[:])
	hash.Sum(r[:0])

	// Calculate R
	rReduced, _ := edwards25519.NewScalar().SetUniformBytes(r[:])
	var R edwards25519.Point
	R.ScalarBaseMult(rReduced)
	encodedR := *(*[32]byte)(R.Bytes())

	// Calculate S
	var hramDigest [64]byte
	hash.Reset()
	hash.Write(encodedR[:])
	hash.Write(publicKey[:])
	hash.Write(message)
	hash.Sum(hramDigest[:0])
	hramDigestReduced, _ := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])

	sScalar := edwards25519.NewScalar().MultiplyAdd(hramDigestReduced, privateKeyScalar, rReduced)
	s := *(*[32]byte)(sScalar.Bytes())

	var signature [64]byte
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
	signature[63] |= publicKey[31] & 0x80

	return signature
}

func TestGenerateXEdDSAVectors(t *testing.T) {
	vectors := TestVectorSet{
		Version:     "1.0",
		Description: "XEdDSA test vectors for iOS/Swift compatibility validation",
	}

	// 1. Key Generation Vectors
	seeds := [][32]byte{
		// All zeros
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// Sequential bytes
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		// All 0xFF (tests all bits need clamping)
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	descriptions := []string{"all zeros", "sequential bytes", "all 0xFF"}

	for i, seed := range seeds {
		priv := seed
		clampPrivateKey(&priv)
		pub := computePublicKey(&priv)

		vectors.KeyGeneration = append(vectors.KeyGeneration, KeyGenerationVector{
			Description:       descriptions[i],
			Seed:              hex.EncodeToString(seed[:]),
			ClampedPrivateKey: hex.EncodeToString(priv[:]),
			PublicKey:         hex.EncodeToString(pub[:]),
		})
	}

	// 2. Montgomery to Edwards Conversion Vectors
	montKeys := [][32]byte{
		// u = 0 should give y = -1 = p - 1
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// u = 9 (basepoint)
		{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	montNotes := []string{"u=0 edge case", "basepoint u=9"}

	for i, mont := range montKeys {
		ed := montgomeryToEdwards(mont)
		vectors.MongoToEdwards = append(vectors.MongoToEdwards, MongoToEdwardsVector{
			Description: montNotes[i],
			MontgomeryX: hex.EncodeToString(mont[:]),
			EdwardsY:    hex.EncodeToString(ed[:]),
		})
	}

	// 3. XEdDSA Signing Vectors
	// Use a fixed private key and message
	privKey := [32]byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	}
	clampPrivateKey(&privKey)
	pubKey := computePublicKey(&privKey)

	messages := []struct {
		desc string
		msg  []byte
	}{
		{"empty message", []byte{}},
		{"Hello", []byte("Hello")},
		{"longer message", []byte("This is a longer test message for XEdDSA signing verification.")},
	}

	// Fixed random for deterministic signatures
	var fixedRandom [64]byte
	for i := range fixedRandom {
		fixedRandom[i] = byte(i)
	}

	for _, m := range messages {
		sig := signWithKnownRandom(&privKey, m.msg, fixedRandom)
		signBit := int(sig[63] & 0x80)

		vectors.XEdDSASigning = append(vectors.XEdDSASigning, XEdDSASigningVector{
			Description:  m.desc,
			PrivateKey:   hex.EncodeToString(privKey[:]),
			PublicKey:    hex.EncodeToString(pubKey[:]),
			Message:      string(m.msg),
			MessageHex:   hex.EncodeToString(m.msg),
			SignBit:      signBit,
			SignatureHex: hex.EncodeToString(sig[:]),
		})
	}

	// 4. Signed PreKey Vectors (0x05 prefix)
	identityPriv := privKey
	preKeyPriv := [32]byte{
		0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
		0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
		0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
		0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
	}
	clampPrivateKey(&preKeyPriv)
	preKeyPub := computePublicKey(&preKeyPriv)
	identityPub := computePublicKey(&identityPriv)

	// Message: 0x05 + prekey public key
	preKeyMessage := append([]byte{0x05}, preKeyPub[:]...)

	// Use ecc.CalculateSignature for signed prekey
	eccPriv := ecc.NewDjbECPrivateKey(identityPriv)
	preKeySig := ecc.CalculateSignature(eccPriv, preKeyMessage)

	vectors.SignedPreKey = append(vectors.SignedPreKey, SignedPreKeyVector{
		Description:        "standard signed prekey",
		IdentityPrivateKey: hex.EncodeToString(identityPriv[:]),
		IdentityPublicKey:  hex.EncodeToString(identityPub[:]),
		PreKeyPublicKey:    hex.EncodeToString(preKeyPub[:]),
		MessageToSign:      hex.EncodeToString(preKeyMessage),
		SignatureHex:       hex.EncodeToString(preKeySig[:]),
	})

	// 5. Device Signature Vectors
	deviceDetails := bytes.Repeat([]byte{0xAA}, 50)
	accountSigKey := bytes.Repeat([]byte{0xBB}, 32)
	prefix := []byte{0x06, 0x01} // AdvDeviceSignaturePrefix

	deviceMessage := append(prefix, deviceDetails...)
	deviceMessage = append(deviceMessage, identityPub[:]...)
	deviceMessage = append(deviceMessage, accountSigKey...)

	deviceSig := ecc.CalculateSignature(eccPriv, deviceMessage)

	vectors.DeviceSignature = append(vectors.DeviceSignature, DeviceSignatureVector{
		Description:     "device signature with [6,1] prefix",
		IdentityPrivKey: hex.EncodeToString(identityPriv[:]),
		IdentityPubKey:  hex.EncodeToString(identityPub[:]),
		DeviceDetails:   hex.EncodeToString(deviceDetails),
		AccountSigKey:   hex.EncodeToString(accountSigKey),
		Prefix:          []int{6, 1},
		MessageToSign:   hex.EncodeToString(deviceMessage),
		SignatureHex:    hex.EncodeToString(deviceSig[:]),
	})

	// Output as JSON
	jsonBytes, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println(string(jsonBytes))
	t.Log("Test vectors generated successfully")
}

// TestVerifyGoImplementation verifies the Go XEdDSA implementation works
func TestVerifyGoImplementation(t *testing.T) {
	// Generate a key pair
	privKey := [32]byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	}
	clampPrivateKey(&privKey)
	pubKey := computePublicKey(&privKey)

	message := []byte("Test message for verification")

	// Sign using ecc.CalculateSignature
	eccPriv := ecc.NewDjbECPrivateKey(privKey)
	eccPub := ecc.NewDjbECPublicKey(pubKey)
	sig := ecc.CalculateSignature(eccPriv, message)

	// Verify
	valid := ecc.VerifySignature(eccPub, message, sig)
	if !valid {
		t.Error("Signature verification failed")
	}

	t.Log("Go XEdDSA implementation verified successfully")
}
