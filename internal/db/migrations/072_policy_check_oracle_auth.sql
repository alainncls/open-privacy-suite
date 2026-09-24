-- Restrict policy-check audit rows to the dedicated cross-org oracle identity.
-- This is separate from 071 so environments that exercised the PR before its
-- architecture hardening receive the constraint update on migration.

ALTER TABLE policy_check_log
    DROP CONSTRAINT IF EXISTS policy_check_log_caller_auth_method_chk;

ALTER TABLE policy_check_log
    ADD CONSTRAINT policy_check_log_caller_auth_method_chk
    CHECK (caller_auth_method = 'cross_org_authorization_oracle_token');

---- create above / drop below ----

ALTER TABLE policy_check_log
    DROP CONSTRAINT IF EXISTS policy_check_log_caller_auth_method_chk;

ALTER TABLE policy_check_log
    ADD CONSTRAINT policy_check_log_caller_auth_method_chk
    CHECK (caller_auth_method IN ('admin_token', 'operator_token'));
