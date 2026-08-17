-- Bind recurring scans to the exact engagement that authorized their creation.
--
-- Existing schedules remain NULL and therefore fail closed until an operator
-- recreates them under an explicit engagement. The application also requires
-- the active engagement to match this snapshot before each execution so later
-- policy changes cannot silently broaden stored work.

ALTER TABLE scan_schedules
    ADD COLUMN engagement_snapshot JSONB;
