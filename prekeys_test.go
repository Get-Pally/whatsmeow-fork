package whatsmeow

import (
	"context"
	"testing"

	"go.mau.fi/whatsmeow/util/keys"
)

type markUploadedPreKeysStub struct {
	called bool
	upToID uint32
	err    error
}

func (s *markUploadedPreKeysStub) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	return nil, nil
}

func (s *markUploadedPreKeysStub) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	return nil, nil
}

func (s *markUploadedPreKeysStub) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	return nil, nil
}

func (s *markUploadedPreKeysStub) RemovePreKey(ctx context.Context, id uint32) error {
	return nil
}

func (s *markUploadedPreKeysStub) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	s.called = true
	s.upToID = upToID
	return s.err
}

func (s *markUploadedPreKeysStub) UploadedPreKeyCount(ctx context.Context) (int, error) {
	return 0, nil
}

func TestMarkUploadedPreKeysSkipsEmptyBatch(t *testing.T) {
	store := &markUploadedPreKeysStub{}

	if err := markUploadedPreKeys(t.Context(), store, nil); err != nil {
		t.Fatalf("markUploadedPreKeys returned error for empty batch: %v", err)
	}
	if store.called {
		t.Fatal("expected empty prekey batch to skip MarkPreKeysAsUploaded")
	}
}

func TestMarkUploadedPreKeysMarksNewestKey(t *testing.T) {
	store := &markUploadedPreKeysStub{}
	preKeys := []*keys.PreKey{
		{KeyID: 11},
		{KeyID: 42},
		{KeyID: 77},
	}

	if err := markUploadedPreKeys(t.Context(), store, preKeys); err != nil {
		t.Fatalf("markUploadedPreKeys returned error: %v", err)
	}
	if !store.called {
		t.Fatal("expected MarkPreKeysAsUploaded to be called")
	}
	if store.upToID != 77 {
		t.Fatalf("unexpected uploaded prekey marker: got %d want %d", store.upToID, 77)
	}
}
