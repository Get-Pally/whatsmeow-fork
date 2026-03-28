-- v13: Scrub persisted companion bootstrap and ADV state from transport-only devices.
UPDATE whatsmeow_device
SET registration_id = 0,
    identity_key = repeat(E'\\000', 32)::bytea,
    signed_pre_key = repeat(E'\\000', 32)::bytea,
    signed_pre_key_id = 0,
    signed_pre_key_sig = repeat(E'\\000', 64)::bytea,
    adv_key = repeat(E'\\000', 32)::bytea,
    adv_details = ''::bytea,
    adv_account_sig = repeat(E'\\000', 64)::bytea,
    adv_account_sig_key = repeat(E'\\000', 32)::bytea,
    adv_device_sig = repeat(E'\\000', 64)::bytea
WHERE transport_only = TRUE;
