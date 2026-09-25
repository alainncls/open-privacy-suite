-- RD-872 follow-up: dry-run can return decision=indeterminate when nested
-- execution reaches a foreign organization. Persist that outcome accurately in
-- the audit trail instead of recording a definitive deny.

ALTER TABLE impersonation_log DROP CONSTRAINT impersonation_decision_chk;
ALTER TABLE impersonation_log ADD CONSTRAINT impersonation_decision_chk
    CHECK (decision IN ('allow', 'deny', 'error', 'indeterminate'));

---- create above / drop below ----

ALTER TABLE impersonation_log DROP CONSTRAINT impersonation_decision_chk;
ALTER TABLE impersonation_log ADD CONSTRAINT impersonation_decision_chk
    CHECK (decision IN ('allow', 'deny', 'error'));
