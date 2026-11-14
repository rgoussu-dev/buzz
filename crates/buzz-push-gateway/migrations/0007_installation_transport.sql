SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Mirrored by relay migration 0089. Which push service an installation's
-- endpoint belongs to: every existing installation is an APNs one, which the
-- constant default records without rewriting rows. The check is added NOT
-- VALID so this write-blocking DDL does not scan existing rows; 0008
-- validates it.
ALTER TABLE push_gateway_installations
    ADD COLUMN transport TEXT NOT NULL DEFAULT 'apns',
    ADD CONSTRAINT push_gateway_installations_transport_check
        CHECK (transport IN ('apns', 'webpush')) NOT VALID;
