-- 002_rls.sql
-- Database-enforced tenant isolation via PostgreSQL Row-Level Security (RLS).
--
-- The whole point of this lab: even if the application forgets its
-- `WHERE tenant_id = ...` clause, the database refuses to return rows that
-- belong to other tenants. Isolation is enforced one layer below the app, so an
-- app-layer bug can no longer leak cross-tenant data.
--
-- Four things must all be true for that guarantee to hold (a non-superuser
-- owner, a non-owner app role, ENABLE+FORCE, and the policies). Each is called
-- out with WHY below, because each is a classic mistake that silently disables
-- RLS.

-- ---------------------------------------------------------------------------
-- (0) A dedicated NON-SUPERUSER table owner.
--
-- WHY reassign ownership away from the bootstrap `postgres` superuser:
--   These migrations run (via docker-entrypoint-initdb.d, or by hand) as the
--   `postgres` superuser, so the tables in 001 were created owned by postgres.
--   A SUPERUSER bypasses RLS UNCONDITIONALLY -- even under FORCE -- so as long
--   as a superuser owns the tables, `FORCE ROW LEVEL SECURITY` (section 2)
--   buys nothing against the owner: a migration/cron/admin job connecting as
--   that owner would still read every tenant's rows. FORCE only genuinely
--   closes the ownership back door when the owner is a NON-superuser.
--
--   So we create `app_owner` -- NOSUPERUSER, NOBYPASSRLS, and NOLOGIN (it only
--   owns objects; nobody connects as it) -- and hand it the tables. Now FORCE
--   actually binds the owner, and the demo matches its own claim.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_owner') THEN
        CREATE ROLE app_owner NOSUPERUSER NOBYPASSRLS NOLOGIN;
    ELSE
        -- Idempotent re-run: pin the security-relevant attributes.
        ALTER ROLE app_owner NOSUPERUSER NOBYPASSRLS NOLOGIN;
    END IF;
END
$$;

ALTER TABLE tenants OWNER TO app_owner;
ALTER TABLE items   OWNER TO app_owner;

-- ---------------------------------------------------------------------------
-- (1) The non-owner application role.
--
-- WHY a separate, non-owner role:
--   RLS is NOT enforced against the table owner by default, and a superuser
--   bypasses it entirely. If the app connected as the postgres/superuser or as
--   the table owner, every policy below would be silently ignored. So the app
--   MUST connect as a dedicated role that:
--     * is NOT a superuser,
--     * does NOT own the tables (owner is the non-superuser `app_owner`, above),
--     * has NOBYPASSRLS (cannot opt out of policies).
--
-- Password is a dev-only local value; real deployments inject a secret.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user LOGIN PASSWORD 'app_user' NOSUPERUSER NOBYPASSRLS;
    ELSE
        -- Make re-runs idempotent and pin the security-relevant attributes.
        ALTER ROLE app_user NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

-- The app role needs to reach the objects, but grants alone do NOT weaken RLS:
-- a row still has to pass the policy after the grant lets the statement run.
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON items   TO app_user;

-- ---------------------------------------------------------------------------
-- (2) ENABLE + FORCE Row-Level Security.
--
-- WHY FORCE (not just ENABLE):
--   ENABLE turns policies on for everyone EXCEPT the table owner. That means a
--   migration or job running as the owner would still see all tenants' rows --
--   an easy way to leak in practice. FORCE applies the policies to the owner
--   too, so there is no privileged back door through ownership. We use both.
--   (This only bites because section 0 made the owner a NON-superuser: a
--   superuser owner would still bypass RLS regardless of FORCE.)
-- ---------------------------------------------------------------------------
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE  ROW LEVEL SECURITY;

ALTER TABLE items ENABLE ROW LEVEL SECURITY;
ALTER TABLE items FORCE  ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- (3) The isolation policies.
--
-- WHY current_setting('app.tenant_id', true)::uuid:
--   `app.tenant_id` is a custom GUC (session/transaction variable) that the
--   application sets once per request to the caller's tenant (see app/db.py).
--   The policy compares each row's tenant_id against that variable, so the
--   database -- not the app -- decides visibility.
--
--   The second argument `true` (missing_ok) makes current_setting return NULL
--   instead of raising when the GUC was never set. That is deliberate and
--   fail-CLOSED: `tenant_id = NULL` is NULL (never true), so a request that
--   forgot to set the tenant context sees ZERO rows rather than all of them.
--
-- WHY NULLIF(..., '') around the cast:
--   `missing_ok` only covers the NEVER-set case (NULL). A GUC that was set to an
--   EMPTY STRING -- a realistic leftover on a pooled connection after a RESET --
--   would reach `''::uuid`, which raises `invalid input syntax for type uuid`.
--   Inside a policy that error ABORTS the whole statement/transaction instead of
--   failing closed. NULLIF(current_setting(...), '') turns '' back into NULL, so
--   BOTH an unset and a blank context return zero rows cleanly, never an error.
--
-- USING controls which existing rows are visible/updatable/deletable.
-- WITH CHECK controls which rows may be inserted/updated -- it blocks a tenant
--   from writing a row stamped with someone else's tenant_id.
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS tenant_isolation ON items;
CREATE POLICY tenant_isolation ON items
    USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- For the tenants table the tenant's own id is the isolation key: a tenant may
-- only see (and touch) its own tenant row.
DROP POLICY IF EXISTS tenant_self_isolation ON tenants;
CREATE POLICY tenant_self_isolation ON tenants
    USING      (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
