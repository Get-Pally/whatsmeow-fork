-- v12: Mark transport-only relay devices explicitly.
ALTER TABLE whatsmeow_device
	ADD COLUMN transport_only BOOLEAN NOT NULL DEFAULT false;
