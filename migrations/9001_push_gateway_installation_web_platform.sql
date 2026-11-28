-- Fork migration (rgoussu-dev/buzz): numbered from 9001 so it never collides
-- with an upstream migration number.
--
-- A browser installation (Web Push) is a third platform. Widen the platform
-- check to admit it. Expand only: every value the deployed gateway writes
-- ('ios', 'android') stays valid, and a gateway from before this change reads
-- no 'web' row it could mistake for a device token (it rejects the unknown
-- platform). The new check is added NOT VALID so no scan runs under the
-- ACCESS EXCLUSIVE lock; the next migration validates it.
SET LOCAL lock_timeout = '5s';
ALTER TABLE push_gateway_installations
    DROP CONSTRAINT IF EXISTS push_gateway_installations_platform_check,
    ADD CONSTRAINT push_gateway_installations_platform_check
        CHECK (platform IN ('ios', 'android', 'web')) NOT VALID;
