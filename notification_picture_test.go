package whatsmeow

import (
	"context"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestHandlePictureNotificationUsesParentFromAndHashFallback(t *testing.T) {
	cli := &Client{Log: waLog.Noop}

	var pictureEvt *events.Picture
	cli.AddEventHandler(func(evt any) {
		if typed, ok := evt.(*events.Picture); ok {
			pictureEvt = typed
		}
	})

	cli.handlePictureNotification(context.Background(), &waBinary.Node{
		Tag: "notification",
		Attrs: waBinary.Attrs{
			"type": "picture",
			"from": types.NewJID("43285183762587", "lid"),
			"t":    "1700000000",
		},
		Content: []waBinary.Node{{
			Tag: "set",
			Attrs: waBinary.Attrs{
				"hash": "PUWf",
			},
		}},
	})

	if pictureEvt == nil {
		t.Fatal("expected picture event to be dispatched")
	}
	if got := pictureEvt.JID.String(); got != "43285183762587@lid" {
		t.Fatalf("unexpected picture jid: %s", got)
	}
	if pictureEvt.PictureID != "PUWf" {
		t.Fatalf("unexpected picture id: %s", pictureEvt.PictureID)
	}
	if pictureEvt.Remove {
		t.Fatal("did not expect picture update to be marked as remove")
	}
}

func TestHandlePictureNotificationIgnoresSetWithoutTargetOrID(t *testing.T) {
	cli := &Client{Log: waLog.Noop}

	dispatched := false
	cli.AddEventHandler(func(evt any) {
		if _, ok := evt.(*events.Picture); ok {
			dispatched = true
		}
	})

	cli.handlePictureNotification(context.Background(), &waBinary.Node{
		Tag:   "notification",
		Attrs: waBinary.Attrs{"type": "picture", "t": "1700000000"},
		Content: []waBinary.Node{{
			Tag: "set",
		}},
	})

	if dispatched {
		t.Fatal("did not expect invalid picture notification to dispatch an event")
	}
}
