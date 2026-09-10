-- 001_schema.sql
-- Generic, self-contained multi-tenant schema.
--
-- WHY this shape:
--   Every tenant-owned row carries an explicit `tenant_id`. That column is the
--   single key the database uses to decide, in 002_rls.sql, which rows a given
--   request is allowed to see. Keeping isolation keyed on one column keeps the
--   Row-Level Security policies trivial to read and hard to get wrong.
--
-- This file only defines structure. All isolation lives in 002_rls.sql so the
-- security model is reviewable in one place.

-- gen_random_uuid() is a core function since PostgreSQL 13, so no extension is
-- required on the postgres:16 image used by docker-compose.

-- ---------------------------------------------------------------------------
-- tenants: one row per tenant (the "customer" boundary).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- items: a generic tenant-owned resource. The exact columns are irrelevant to
-- the pattern; what matters is that `tenant_id` scopes ownership and is NOT
-- NULL, so no row can ever exist outside a tenant.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS items (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name        text        NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- The RLS policy filters on tenant_id on every query, so index it.
CREATE INDEX IF NOT EXISTS items_tenant_id_idx ON items (tenant_id);
