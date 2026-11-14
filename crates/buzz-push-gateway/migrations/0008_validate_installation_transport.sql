SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Mirrored by relay migration 0090. Validate separately from the
-- write-blocking DDL transaction.
ALTER TABLE push_gateway_installations
    VALIDATE CONSTRAINT push_gateway_installations_transport_check;
