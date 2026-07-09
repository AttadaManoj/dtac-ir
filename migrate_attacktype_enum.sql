-- Migration: extend attacktype enum to match ML model output classes
-- Run this once against your existing dtac_ir database (it will fail harmlessly
-- if the values already exist, so it's safe to re-run).
--
-- Usage:
--   docker exec -i dtac_postgres psql -U dtac_user -d dtac_ir < migrate_attacktype_enum.sql

ALTER TYPE attacktype ADD VALUE IF NOT EXISTS 'BOTNET';
ALTER TYPE attacktype ADD VALUE IF NOT EXISTS 'DOS';
ALTER TYPE attacktype ADD VALUE IF NOT EXISTS 'WEB_ATTACK';
