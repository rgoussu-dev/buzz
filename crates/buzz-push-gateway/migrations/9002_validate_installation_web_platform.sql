-- Fork migration (rgoussu-dev/buzz). Validate the widened platform check
-- under a SHARE UPDATE EXCLUSIVE lock, which blocks no reads or writes. Every
-- existing row already satisfied the narrower check it replaces.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
ALTER TABLE push_gateway_installations
    VALIDATE CONSTRAINT push_gateway_installations_platform_check;
