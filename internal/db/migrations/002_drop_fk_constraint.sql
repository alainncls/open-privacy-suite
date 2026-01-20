-- Drop legacy foreign key constraint from access_logs
-- This constraint was removed to allow logging access for unknown external IDs

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'access_logs_external_id_fkey'
    ) THEN
        ALTER TABLE access_logs DROP CONSTRAINT access_logs_external_id_fkey;
    END IF;
END $$;

---- create above / drop below ----

-- No down migration: we don't want to re-add this constraint
