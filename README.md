# multi-tenant-rls-isolation-lab

**The app forgot `WHERE tenant_id = ...`. What does the database return?**

- **Without RLS** — other tenants' rows. A single missing clause leaks every customer's data.
- **With `FORCE ROW LEVEL SECURITY` and a non-owner application role** — nothing but the current tenant's own rows.

This repository is a small, self-contained demonstration of **database-enforced
tenant isolation** in PostgreSQL. It proves the guarantee with a test that
deliberately omits the `WHERE tenant_id` filter and shows the data does not leak.

No business logic, no clients, no real credentials — just the pattern.

---

## The break test (the point of the repo)

`tests/test_break_isolation.py` runs `SELECT * FROM items` with **no**
`WHERE tenant_id` clause, under tenant A's context, and asserts that only tenant
A's rows come back. It contrasts that with an owner/`BYPASSRLS` connection, which
*does* leak — proving the isolation is real and comes from `FORCE` RLS + the
non-owner role, not from the query.

Real output, captured from `pytest -s` run against a live PostgreSQL with the
migrations applied:

```
$ make test          # APP_DSN=... pytest -q  (against the running Postgres)
............                                                             [100%]
12 passed in 0.35s

====================================================================
break-isolation transcript
====================================================================
app_user @ tenant A, `SELECT id, tenant_id, name FROM items` (NO WHERE): 2 rows -> ['A-alpha', 'A-beta']  [only A -> RLS holds]
app_user @ tenant B, same query (NO WHERE): 1 rows -> ['B-gamma']  [only B -> RLS holds]
app_user with app.tenant_id NEVER set, same query (NO WHERE): 0 rows  [fail-closed, not fail-open]
postgres (superuser), SAME query (NO WHERE): >= 2 tenants visible incl. A AND B  [LEAKS -- RLS bypassed]
  -> same SQL, two roles: app_user sees 1 tenant, superuser sees 2. The isolation is the difference.
mechanism (throwaway table, 3 rows: A=2, B=1, context=A):
  ENABLE-only, owner reads    -> 3 rows  [owner exempt -> LEAKS]
  + FORCE, owner reads        -> 2 rows  [owner now bound -> contained]
  FORCE, BYPASSRLS role reads -> 3 rows  [bypass wins -> LEAKS]
====================================================================
```

Read the last three lines together: the **exact same** `SELECT ... FROM items`
with no `WHERE` returns one tenant for `app_user`, both tenants for the
superuser, and — in the isolated mechanism check — leaks under plain `ENABLE`
but is contained the moment `FORCE` is added. The safety is in the setup, not in
the SQL.

---

## How it works

Three things must all be true, or RLS silently does nothing:

1. **A policy keyed on the tenant.** Each tenant-owned table has a policy:
   ```sql
   USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
   ```
   The app sets the `app.tenant_id` GUC (a per-request context variable) once at
   the start of each request; the database then filters every statement by it.
   The policy fails **closed** for a missing context: the `true` (missing_ok)
   argument returns `NULL` when the GUC was never set, `NULLIF(..., '')` turns a
   blank leftover back into `NULL`, and `tenant_id = NULL` is never true — so
   both an unset and an empty context see zero rows rather than erroring or
   leaking. (Without the `NULLIF`, an empty-string GUC would reach `''::uuid` and
   raise `invalid input syntax for type uuid`, aborting the statement.)

2. **A dedicated non-superuser owner + `FORCE ROW LEVEL SECURITY`.** Plain
   `ENABLE` exempts the table owner, so a job running as the owner would still
   see everything; `FORCE` applies the policy to the owner too. But `FORCE` only
   means something if the owner is *not* a superuser (a superuser bypasses RLS
   unconditionally). So the migrations reassign the tables to a dedicated
   `app_owner` role created `NOSUPERUSER NOBYPASSRLS` — closing the ownership
   back door for real, not just on paper.

3. **A non-owner, `NOBYPASSRLS`, non-superuser application role.** RLS does not
   apply to the table owner (without `FORCE`) and is bypassed by superusers and
   `BYPASSRLS` roles. The app connects as `app_user`, which is none of those, so
   the policies actually bind.

Layout:

```
migrations/
  001_schema.sql   tenants + items (items.tenant_id uuid NOT NULL)
  002_rls.sql      non-superuser app_owner + ENABLE/FORCE RLS + policies + app_user role
app/
  db.py            psycopg (v3) connection; SET app.tenant_id per request
  main.py          minimal FastAPI read endpoints
tests/
  test_isolation.py        normal isolation between two tenants
  test_break_isolation.py  "forgot WHERE" -> RLS holds; owner/BYPASSRLS leaks
docker-compose.yml  postgres:16, runs migrations on init
Makefile            up / migrate / test / down
```

Run it:

```bash
make up      # start Postgres (Docker); migrations apply on first init
make test    # run the suite against the real database
make down    # stop and wipe
```

No Docker? Any PostgreSQL works — the tests read their connection strings from
the environment. Create a `rls_lab` database and apply `migrations/001_schema.sql`
then `migrations/002_rls.sql` as a **superuser** (002 creates the roles and
reassigns the tables to the non-superuser `app_owner`, then the app connects as
the non-owner `app_user`), and run the suite.

The bootstrap superuser name is environment-specific: the Docker image ships a
`postgres` superuser, but a local Homebrew / `initdb` cluster usually makes the
superuser your **OS username** instead — so `psql -U postgres` fails with *role
"postgres" does not exist* until you create one. Use whatever your cluster has:
either `createuser -s postgres` first, or apply the migrations as `-U $(whoami)`
and set `ADMIN_DSN` / `SUPERUSER_DSN` to that superuser. For example:

```bash
APP_DSN=postgresql://app_user:app_user@localhost:5432/rls_lab \
ADMIN_DSN=postgresql://$(whoami)@localhost:5432/rls_lab \
SUPERUSER_DSN=postgresql://$(whoami)@localhost:5432/rls_lab \
pytest -q
```

If no database is reachable the suite **skips with a clear reason** instead of
erroring, so a checkout without a running Postgres stays green-by-omission
rather than failing noisily.

---

## Why this is commercially valuable

Tenant data isolation is a **top security requirement for any SaaS** and one of
the most common serious findings in audits and penetration tests: customer A
being able to read customer B's data is a direct breach, a compliance failure,
and a reputational event.

The usual defense — remembering to add `WHERE tenant_id = ...` on every query —
is a control that lives in application code and fails the moment one developer,
one ORM path, one new endpoint, or one reporting query forgets it. That is a
*when*, not an *if*.

Row-Level Security moves the boundary **into the database**, one layer below the
application:

- **Defense in depth.** An app-layer bug that omits the tenant filter no longer
  leaks data — the database still refuses the other tenant's rows. The blast
  radius of the single most common multi-tenant mistake drops to zero.
- **Measurable risk reduction.** It converts a whole class of "did every query
  remember the filter?" review effort into one auditable database policy. That
  is exactly the kind of control auditors, security teams, and enterprise buyers
  ask for — and a concrete answer during due diligence and pentests.
- **Cheap and standard.** It is built-in PostgreSQL, not extra infrastructure,
  so the protection costs little to add and nothing extra to run.

In short: a business pays for the assurance that a forgotten `WHERE` clause can
no longer become a cross-tenant data breach.

---

## What I learned

Building this made the failure modes concrete — each is a one-line mistake that
silently turns RLS off while every query still *looks* protected:

- **`ENABLE` is not enough — you need `FORCE`.** `ALTER TABLE ... ENABLE ROW
  LEVEL SECURITY` applies policies to everyone *except the table owner*. Since
  migrations, cron jobs, and admin scripts routinely run as the owner, plain
  `ENABLE` leaves a wide-open back door. The mechanism test proves it directly:
  with `ENABLE` only, the owner reads all 3 rows; add `FORCE` and the same owner
  reads only its tenant's 2. `FORCE` is what binds the owner to its own policy.

- **The application must connect as a non-owner, non-superuser, `NOBYPASSRLS`
  role.** A superuser bypasses RLS entirely (even under `FORCE`), and so does any
  role with the `BYPASSRLS` attribute. In the transcript the `postgres`
  superuser runs the *identical* forgotten-`WHERE` query and sees both tenants —
  that gap between `app_user` (1 tenant) and `postgres` (2 tenants) *is* the
  isolation. So `app_user` is created `NOSUPERUSER NOBYPASSRLS` and never owns the
  tables. Getting this role wrong is the most common way teams "have RLS" that
  does nothing.

- **GUC scoping is a real footgun — transaction scope is the fix.** The tenant
  context is a custom GUC, `app.tenant_id`. Set it **transaction-locally** with
  `set_config('app.tenant_id', <id>, true)` (equivalent to `SET LOCAL`, with
  autocommit off) so PostgreSQL discards it automatically at `COMMIT`/`ROLLBACK`.
  That is what makes the pattern safe behind a connection **pool**: a connection
  handed back to the pool cannot carry a stale tenant into the next request.
  Session scope (`set_config(..., false)`) does **not** reset on its own — and
  "just remember to set it at the start of every request" is *not* a substitute:
  a request that early-returns, validates before setting, or throws between
  checkout and `set_config` would silently inherit the previous tenant's rows,
  with no `WHERE` and no error. Transaction scope removes that footgun
  structurally rather than by discipline. (I originally reached for session scope
  because a fresh connection per request hides the problem; it reappears the
  moment a pool is introduced.)

- **Fail *closed*, not open — and guard the cast.** The policies read
  `NULLIF(current_setting('app.tenant_id', true), '')::uuid`. The `true`
  (`missing_ok`) makes a *never-set* GUC return `NULL`; the `NULLIF(..., '')`
  turns a *blank* GUC (a realistic pooled leftover) back into `NULL` too. Because
  `tenant_id = NULL` is never true, both cases see **zero** rows — verified by the
  `0 rows` line in the transcript. Without the `NULLIF`, an empty-string GUC would
  reach `''::uuid` and raise `invalid input syntax for type uuid`; because that
  fires *inside the policy*, it would abort the whole statement (and poison the
  transaction) rather than failing closed — and no app-side `WHERE` guard could
  prevent it, since the policy's cast runs first.

- **`USING` guards reads, `WITH CHECK` guards writes.** `USING` decides which
  existing rows are visible/updatable/deletable; `WITH CHECK` blocks a tenant
  from *inserting or updating* a row stamped with someone else's `tenant_id`.
  Both are needed — a read-only policy would still let one tenant plant rows in
  another's namespace.

The headline result: the same unsafe SQL is contained for `app_user` and leaks
for the superuser. That contrast is the whole point — the safety comes from
`FORCE` RLS plus a correctly-attributed role, not from remembering the `WHERE`.

---

## Limitations

- This is a **demonstration of one pattern**, not a finished multi-tenant
  platform. There is no business logic.
- RLS is **one layer**. Real systems still need authentication, authorization,
  auditing, encryption in transit/at rest, and backups. RLS complements them; it
  does not replace them.
- The isolation is only as good as the trust boundary around the GUC: whatever
  sets `app.tenant_id` must be trusted to set it to the authenticated tenant.
- The Postgres password in `docker-compose.yml` is a **dev-only local value**.
  Never use it outside this demo.
