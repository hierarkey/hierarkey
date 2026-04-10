-- Add 'pending' status for freshly-created master keys that have never been activated.
-- Distinguishes "just created, waiting to be activated" from "fully decommissioned"
-- (retired). Pending keys are loaded into the keyring at startup so they can be
-- activated without a server restart.
ALTER TYPE masterkey_status ADD VALUE IF NOT EXISTS 'pending';
