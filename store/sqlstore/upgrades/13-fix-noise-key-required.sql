-- v12 -> v13: Fix noise_key to be NOT NULL
-- noise_key is the backend's transport encryption key for the Noise Protocol
-- and MUST always be present. It was incorrectly made nullable in v12.

-- Delete any corrupted devices with NULL noise_key (these can't function anyway)
DELETE FROM whatsmeow_device WHERE noise_key IS NULL;

-- Re-add NOT NULL constraint on noise_key
ALTER TABLE whatsmeow_device ALTER COLUMN noise_key SET NOT NULL;
