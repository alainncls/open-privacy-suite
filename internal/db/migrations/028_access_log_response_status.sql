-- Add response_status column to access_logs for opaque denial tracking.
-- decision status (status_code) records what happened internally (401/403/500).
-- response_status records what the client was told (e.g., 404 for opaque denials).
-- Both are committed to the tamper-evident hash chain for full audit verifiability.
ALTER TABLE access_logs ADD COLUMN response_status INTEGER;
