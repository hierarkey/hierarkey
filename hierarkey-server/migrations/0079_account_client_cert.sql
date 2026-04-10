-- Add mTLS client certificate fields to service accounts.
-- client_cert_fingerprint: SHA-256 fingerprint (hex, colon-separated) of the registered DER cert.
-- client_cert_subject:     Human-readable subject DN for display purposes.
-- The fingerprint column has a partial unique index so one cert can be
-- registered to at most one service account.

ALTER TABLE accounts
    ADD COLUMN client_cert_fingerprint TEXT,
    ADD COLUMN client_cert_subject     TEXT;

-- Enforce uniqueness: two service accounts cannot share a certificate.
CREATE UNIQUE INDEX accounts_client_cert_fingerprint_idx
    ON accounts (client_cert_fingerprint)
    WHERE client_cert_fingerprint IS NOT NULL;
