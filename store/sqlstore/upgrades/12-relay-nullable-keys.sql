-- v11 -> v12: Allow NULL private keys for E2EE relay mode
-- In relay mode, iOS holds the identity and signed pre-key private keys.
-- NOTE: noise_key MUST remain NOT NULL - it's the backend's transport encryption key
-- for the Noise Protocol handshake with WhatsApp servers.

-- Drop existing constraints to rebuild them
ALTER TABLE whatsmeow_device DROP CONSTRAINT IF EXISTS whatsmeow_device_identity_key_check;
ALTER TABLE whatsmeow_device DROP CONSTRAINT IF EXISTS whatsmeow_device_signed_pre_key_check;
ALTER TABLE whatsmeow_device DROP CONSTRAINT IF EXISTS whatsmeow_device_signed_pre_key_sig_check;

-- Allow NULL for identity_key and signed_pre_key (iOS owns these in relay mode)
-- noise_key remains NOT NULL - it's the backend's transport key
ALTER TABLE whatsmeow_device ALTER COLUMN identity_key DROP NOT NULL;
ALTER TABLE whatsmeow_device ALTER COLUMN signed_pre_key DROP NOT NULL;
ALTER TABLE whatsmeow_device ALTER COLUMN signed_pre_key_sig DROP NOT NULL;

-- Re-add CHECK constraints that allow NULL OR correct length
ALTER TABLE whatsmeow_device ADD CONSTRAINT whatsmeow_device_identity_key_check
    CHECK ( identity_key IS NULL OR length(identity_key) = 32 );
ALTER TABLE whatsmeow_device ADD CONSTRAINT whatsmeow_device_signed_pre_key_check
    CHECK ( signed_pre_key IS NULL OR length(signed_pre_key) = 32 );
ALTER TABLE whatsmeow_device ADD CONSTRAINT whatsmeow_device_signed_pre_key_sig_check
    CHECK ( signed_pre_key_sig IS NULL OR length(signed_pre_key_sig) = 64 );
