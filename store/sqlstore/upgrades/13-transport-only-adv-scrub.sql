-- v13: Scrub pairing-only ADV secrets from transport-only devices.
UPDATE whatsmeow_device
SET adv_key = repeat(E'\\000', 32)::bytea
WHERE transport_only = TRUE;
