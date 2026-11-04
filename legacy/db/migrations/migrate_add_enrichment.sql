-- Run this against existing databases to add enrichment columns
-- New installs: columns created automatically via Base.metadata.create_all()
ALTER TABLE findings ADD COLUMN IF NOT EXISTS explanation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS wstg_id VARCHAR(30);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score_v4 FLOAT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS "references" JSON;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_source VARCHAR(20);
