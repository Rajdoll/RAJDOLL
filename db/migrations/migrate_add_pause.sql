-- Run this against existing databases to add pause/resume support
-- New installs: enum value and column created automatically via Base.metadata.create_all()
--
-- NOTE: PostgreSQL requires ALTER TYPE outside a transaction for enum additions.
-- Run this script with psql directly (not inside BEGIN/COMMIT blocks).
ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'paused';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS paused_state JSONB;
