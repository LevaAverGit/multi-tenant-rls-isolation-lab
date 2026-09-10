"""test_break_isolation.py -- the headline artifact of this repo.

This is the "pentest" test. It deliberately writes the single most common
multi-tenant mistake -- ``SELECT * FROM items`` with **no** ``WHERE tenant_id``
clause -- and proves that the database still refuses to leak another tenant's
rows. That is the whole promise of the pattern: isolation lives one layer below
the application, so an app-layer bug (a forgotten filter, a new endpoint, a
reporting query) can no longer become a cross-tenant data breach.

The file is organised as a proof in two halves:

  1. THE GUARANTEE. Connected as the non-owner ``app_user`` role with the
     tenant context pinned, the forgotten-``WHERE`` query returns ONLY the
     current tenant's rows. (This is exactly the query behind
     ``GET /items/unscoped`` in ``app/main.py``.)

  2. THE COUNTER-EXAMPLE. The *same* query, run over a connection that RLS does
     not bind -- the ``postgres`` superuser connection -- DOES return every
     tenant's rows (a superuser bypasses RLS unconditionally, even under
     ``FORCE``). And an isolated mechanism test shows precisely why a non-app
     role leaks: a table owner is exempt from its own policies unless the table
     is declared ``FORCE ROW LEVEL SECURITY``, and a ``BYPASSRLS`` role is exempt
     regardless.

Half 2 is what makes half 1 meaningful: it demonstrates that the query itself is
unsafe, and that the safety in half 1 comes entirely from ``FORCE`` RLS plus a
role that is neither the owner nor a ``BYPASSRLS``/superuser role. Remove any one
of those and the leak returns.

Seeding is done as the superuser (which bypasses RLS, so no GUC juggling is
needed); every tenant we create is torn down afterwards, so the test is
self-contained and repeatable.

Connection strings come from the environment, matching the Makefile:

  * ``APP_DSN``        -> the non-owner ``app_user`` role (the app's connection).
  * ``SUPERUSER_DSN``  -> the ``postgres`` superuser (the leak/counter-example).
"""

import os
from contextlib import contextmanager
from typing import Iterator, List, Optional

import psycopg
import pytest
from psycopg.rows import dict_row

# --------------------------------------------------------------------------- #
# Connection strings. Defaults are the DEV-ONLY local credentials from the
# Makefile / docker-compose; never reuse them anywhere real.
# --------------------------------------------------------------------------- #
APP_DSN = os.environ.get(
    "APP_DSN", "postgresql://app_user:app_user@localhost:5432/rls_lab"
)
SUPERUSER_DSN = os.environ.get(
    "SUPERUSER_DSN", "postgresql://postgres:postgres@localhost:5432/rls_lab"
)

# The exact "forgotten WHERE" query at the heart of the demo. No tenant filter,
# on purpose. It is the same statement app/main.py runs in /items/unscoped.
FORGOTTEN_WHERE_SQL = "SELECT id, tenant_id, name FROM items ORDER BY name"

# A human-readable transcript is accumulated here and printed once at the end of
# the module (visible with ``pytest -s``), ready to paste into the README.
TRANSCRIPT: List[str] = []


def _record(line: str) -> None:
    """Append one line to the README transcript and echo it live."""
    TRANSCRIPT.append(line)
    print(line)


def _skip_if_db_unreachable(dsn: str) -> None:
    """Skip the module cleanly when no Postgres is reachable.

    A fresh checkout with no database should not error out: this pentest needs a
    running Postgres with the migrations applied (``make up``). It skips ONLY on
    a connection/operational failure -- never on an assertion -- so a real leak
    can never hide behind a skip. With a database present the guard is a no-op
    and the full proof (guarantee + counter-example) runs against real SQL.
    """
    try:
        with psycopg.connect(dsn, connect_timeout=3) as probe:
            probe.execute("SELECT 1")
    except psycopg.OperationalError as exc:
        host = dsn.rsplit("@", 1)[-1]  # drop credentials before printing
        pytest.skip(
            f"no Postgres reachable at {host}: {exc.__class__.__name__}. "
            "Run `make up` (Docker) or point APP_DSN/SUPERUSER_DSN at a local "
            "Postgres with migrations/ applied."
        )


@contextmanager
def _app_connection(tenant_id: Optional[str]) -> Iterator[psycopg.Connection]:
    """Open a connection as the non-owner ``app_user`` role.

    Mirrors ``app/db.py``: autocommit is OFF and, when ``tenant_id`` is given,
    the ``app.tenant_id`` GUC is pinned *transaction-locally* (bound as a
    parameter, never string-formatted) inside an explicit transaction, so it
    auto-resets at the end and never leaks across pooled requests. If
    ``tenant_id`` is ``None``, the GUC is left unset on purpose -- to exercise
    the fail-closed path where a request that forgot to establish its tenant
    context sees zero rows rather than everything.
    """
    conn = psycopg.connect(APP_DSN, row_factory=dict_row)  # autocommit off
    try:
        with conn.transaction():
            if tenant_id is not None:
                conn.execute(
                    "SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),)
                )
            yield conn
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module", autouse=True)
def _emit_transcript() -> Iterator[None]:
    """Print the collected transcript once, framed, after the module's tests."""
    TRANSCRIPT.clear()
    yield
    banner = "=" * 68
    print("\n" + banner)
    print("break-isolation transcript")
    print(banner)
    for line in TRANSCRIPT:
        print(line)
    print(banner)


@pytest.fixture(scope="module")
def seed() -> Iterator[dict]:
    """Seed two tenants (A, B) with distinct items, as the superuser.

    Superuser bypasses RLS, so rows for both tenants can be inserted from one
    connection with no ``app.tenant_id`` juggling. Returns the tenant ids and
    the item names we expect each tenant to own; tears everything down after the
    module (deleting the tenants cascades to their items).
    """
    # Both roles must be reachable: the superuser seeds/counter-examples, the
    # app_user proves containment. Probe both so the skip reason is accurate.
    _skip_if_db_unreachable(SUPERUSER_DSN)
    _skip_if_db_unreachable(APP_DSN)
    with psycopg.connect(SUPERUSER_DSN, autocommit=True, row_factory=dict_row) as su:
        tenant_a = su.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            ("break-test-tenant-A",),
        ).fetchone()["id"]
        tenant_b = su.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            ("break-test-tenant-B",),
        ).fetchone()["id"]

        su.execute(
            "INSERT INTO items (tenant_id, name) VALUES (%s, %s), (%s, %s)",
            (tenant_a, "A-alpha", tenant_a, "A-beta"),
        )
        su.execute(
            "INSERT INTO items (tenant_id, name) VALUES (%s, %s)",
            (tenant_b, "B-gamma"),
        )

    data = {
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "a_names": {"A-alpha", "A-beta"},
        "b_names": {"B-gamma"},
    }
    yield data

    with psycopg.connect(SUPERUSER_DSN, autocommit=True) as su:
        su.execute(
            "DELETE FROM tenants WHERE id = ANY(%s)", ([tenant_a, tenant_b],)
        )


# --------------------------------------------------------------------------- #
# Trust precondition -- the proof must not be able to pass vacuously.
# --------------------------------------------------------------------------- #
def test_app_connection_is_a_non_owner_non_bypass_role(seed: dict) -> None:
    """Guard: APP_DSN resolves to a role RLS actually binds.

    Everything below proves isolation *through* the ``app_user`` connection. If
    APP_DSN were accidentally pointed at a superuser, an owner, or a BYPASSRLS
    role, the policies would not apply and every containment assertion in this
    file would pass while proving nothing. Assert the precondition explicitly so
    the headline pentest can never succeed vacuously from an over-privileged
    connection.
    """
    with _app_connection(seed["tenant_a"]) as conn:
        who = conn.execute(
            "SELECT current_user AS role, "
            "current_setting('is_superuser') AS is_superuser"
        ).fetchone()
        bypasses_rls = conn.execute(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()["rolbypassrls"]

    assert who["role"] == "app_user", "the app path must connect as app_user"
    assert who["is_superuser"] == "off", "app_user must not be a superuser"
    assert bypasses_rls is False, "app_user must be NOBYPASSRLS"


# --------------------------------------------------------------------------- #
# Half 1 -- THE GUARANTEE: the forgotten WHERE is contained by RLS.
# --------------------------------------------------------------------------- #
def test_forgotten_where_returns_only_own_tenant(seed: dict) -> None:
    """`SELECT * FROM items` with NO WHERE, as app_user under tenant A.

    This is the core assertion of the whole repository. Despite the missing
    tenant filter, only tenant A's rows come back -- tenant B's row is invisible.
    """
    with _app_connection(seed["tenant_a"]) as conn:
        rows = conn.execute(FORGOTTEN_WHERE_SQL).fetchall()

    names = {r["name"] for r in rows}
    seen_tenants = {r["tenant_id"] for r in rows}

    assert names == seed["a_names"], "app_user must see exactly tenant A's items"
    assert seen_tenants == {seed["tenant_a"]}, "every returned row must belong to A"
    assert seed["tenant_b"] not in seen_tenants, "tenant B must never appear"

    _record(
        "app_user @ tenant A, `SELECT id, tenant_id, name FROM items` (NO WHERE): "
        f"{len(rows)} rows -> {sorted(names)}  [only A -> RLS holds]"
    )


def test_forgotten_where_is_contained_for_the_other_tenant(seed: dict) -> None:
    """The same forgotten-WHERE query, now under tenant B, returns only B.

    Runs the identical statement under a different tenant context to show the
    boundary is symmetric: the database, not the query, decides visibility.
    """
    with _app_connection(seed["tenant_b"]) as conn:
        rows = conn.execute(FORGOTTEN_WHERE_SQL).fetchall()

    names = {r["name"] for r in rows}
    seen_tenants = {r["tenant_id"] for r in rows}

    assert names == seed["b_names"], "app_user must see exactly tenant B's items"
    assert seen_tenants == {seed["tenant_b"]}, "every returned row must belong to B"

    _record(
        "app_user @ tenant B, same query (NO WHERE): "
        f"{len(rows)} rows -> {sorted(names)}  [only B -> RLS holds]"
    )


def test_missing_tenant_context_fails_closed(seed: dict) -> None:
    """A connection that never set app.tenant_id sees ZERO rows, not all rows.

    `current_setting('app.tenant_id', true)` returns NULL when unset, and
    `tenant_id = NULL` is never true -- so a request that forgot to establish
    its tenant context leaks nothing. Fail-closed, the safe default.
    """
    with _app_connection(tenant_id=None) as conn:
        rows = conn.execute(FORGOTTEN_WHERE_SQL).fetchall()

    assert rows == [], "an unset tenant context must return no rows (fail-closed)"

    _record(
        "app_user with app.tenant_id NEVER set, same query (NO WHERE): "
        "0 rows  [fail-closed, not fail-open]"
    )


def test_blank_tenant_context_fails_closed_not_error(seed: dict) -> None:
    """A GUC set to '' returns ZERO rows -- it must not raise a cast error.

    Guards the `NULLIF(current_setting(...), '')` in the policies. `missing_ok`
    alone only covers the never-set case; a blank GUC (a realistic pooled
    leftover after RESET) would reach `''::uuid` and raise `invalid input syntax
    for type uuid`. Because that fires inside the policy it aborts the statement
    instead of failing closed. The NULLIF turns '' back into NULL, so a blank
    context is contained exactly like an unset one. Drop the NULLIF from
    002_rls.sql and this test goes red where the unset-context test stays green.
    """
    with _app_connection(tenant_id=None) as conn:
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", ("",))
        rows = conn.execute(FORGOTTEN_WHERE_SQL).fetchall()

    assert rows == [], "a blank tenant context must return no rows, not error"


# --------------------------------------------------------------------------- #
# Half 2 -- THE COUNTER-EXAMPLE: the same query leaks where RLS does not bind.
# --------------------------------------------------------------------------- #
def test_same_query_leaks_across_tenants_for_superuser(seed: dict) -> None:
    """The identical forgotten-WHERE query LEAKS when RLS does not bind it.

    The `postgres` superuser connection bypasses Row-Level Security (a superuser
    is exempt even under FORCE, regardless of who owns the table). Running the
    *exact same* statement there returns rows from BOTH tenants. This is the
    proof that the query itself is unsafe -- half 1 was made safe purely by the
    app_user + FORCE RLS setup, not by anything in the SQL.
    """
    with psycopg.connect(SUPERUSER_DSN, autocommit=True, row_factory=dict_row) as su:
        rows = su.execute(FORGOTTEN_WHERE_SQL).fetchall()

    seen_tenants = {r["tenant_id"] for r in rows}

    # The privileged connection sees across the tenant boundary...
    assert seed["tenant_a"] in seen_tenants, "superuser should see tenant A's rows"
    assert seed["tenant_b"] in seen_tenants, "superuser should see tenant B's rows"
    assert len(seen_tenants) >= 2, "the same query leaks cross-tenant for superuser"

    # ...while an app_user connection under A, running the SAME query, does not.
    with _app_connection(seed["tenant_a"]) as conn:
        app_tenants = {r["tenant_id"] for r in conn.execute(FORGOTTEN_WHERE_SQL)}
    assert app_tenants == {seed["tenant_a"]}
    assert app_tenants != seen_tenants, "the two connections must disagree -- that gap IS the isolation"

    _record(
        "postgres (superuser), SAME query (NO WHERE): "
        f">= {len(seen_tenants)} tenants visible incl. A AND B  [LEAKS -- RLS bypassed]"
    )
    _record(
        "  -> same SQL, two roles: app_user sees 1 tenant, superuser sees "
        f"{len(seen_tenants)}. The isolation is the difference."
    )


def test_force_rls_and_bypassrls_are_the_mechanism(seed: dict) -> None:
    """Isolate *why* app_user is safe: FORCE (vs ENABLE) and NOBYPASSRLS.

    The superuser leak above conflates two exemptions (owner AND superuser). This
    test separates the FORCE dimension cleanly, in a throwaway table inside a
    rolled-back transaction, using ``SET ROLE`` so no extra login/password or
    schema pollution is needed:

      * A table owned by a plain (non-superuser) role, with RLS merely ENABLEd,
        does NOT bind its owner -- the owner sees every tenant's rows (leak).
      * Declaring the table FORCE ROW LEVEL SECURITY binds the owner too -- the
        owner now sees only the current tenant's rows.
      * A BYPASSRLS role is exempt even under FORCE -- which is exactly why the
        real app_user is created NOBYPASSRLS.

    Nothing here is committed: the transaction is rolled back, so the temporary
    role, table and policy never persist.
    """
    conn = psycopg.connect(SUPERUSER_DSN)  # autocommit off -> everything rolls back
    try:
        cur = conn.cursor()
        # Re-run safety: if a previous run was hard-killed after these objects
        # were created but before the rollback, drop any orphans first so a
        # crashed run can never poison the next one with "already exists".
        cur.execute("DROP TABLE IF EXISTS rls_demo")
        cur.execute("DROP ROLE IF EXISTS rls_demo_owner")
        cur.execute("DROP ROLE IF EXISTS rls_demo_bypass")
        # Two non-superuser roles: one will own the demo table, one has BYPASSRLS.
        cur.execute("CREATE ROLE rls_demo_owner NOSUPERUSER NOBYPASSRLS")
        cur.execute("CREATE ROLE rls_demo_bypass NOSUPERUSER BYPASSRLS")

        # A minimal tenant-scoped table, owned by the plain (non-superuser) role.
        cur.execute("CREATE TABLE rls_demo (tenant text NOT NULL, val text)")
        cur.execute("ALTER TABLE rls_demo OWNER TO rls_demo_owner")
        cur.execute(
            "INSERT INTO rls_demo VALUES ('A', 'a1'), ('A', 'a2'), ('B', 'b1')"
        )
        cur.execute(
            "CREATE POLICY p ON rls_demo "
            "USING (tenant = current_setting('app.demo_tenant', true))"
        )
        # The BYPASSRLS role is not the owner, so it needs a table-level grant to
        # run the query at all. RLS is a ROW filter applied AFTER table
        # privileges -- without the grant we'd hit "permission denied for table",
        # which is a different check and would muddy what this test proves.
        cur.execute("GRANT SELECT ON rls_demo TO rls_demo_bypass")
        # Pin the demo tenant context to A for the rest of this transaction.
        cur.execute("SELECT set_config('app.demo_tenant', 'A', true)")

        def count_as(role: str) -> int:
            cur.execute(f"SET ROLE {role}")
            n = cur.execute("SELECT count(*) FROM rls_demo").fetchone()[0]
            cur.execute("RESET ROLE")
            return n

        # (a) ENABLE only -> owner is EXEMPT -> sees all 3 rows (the leak).
        cur.execute("ALTER TABLE rls_demo ENABLE ROW LEVEL SECURITY")
        owner_enable = count_as("rls_demo_owner")
        assert owner_enable == 3, (
            "with ENABLE (not FORCE) the table owner bypasses its own policy"
        )

        # (b) FORCE -> owner is now BOUND -> sees only tenant A's 2 rows.
        cur.execute("ALTER TABLE rls_demo FORCE ROW LEVEL SECURITY")
        owner_force = count_as("rls_demo_owner")
        assert owner_force == 2, (
            "FORCE ROW LEVEL SECURITY must bind the owner to the policy"
        )

        # (c) A BYPASSRLS role is exempt even under FORCE -> sees all 3 rows.
        bypass_force = count_as("rls_demo_bypass")
        assert bypass_force == 3, (
            "a BYPASSRLS role ignores policies -- why app_user is NOBYPASSRLS"
        )

        _record(
            "mechanism (throwaway table, 3 rows: A=2, B=1, context=A):"
        )
        _record(
            f"  ENABLE-only, owner reads    -> {owner_enable} rows  [owner exempt -> LEAKS]"
        )
        _record(
            f"  + FORCE, owner reads        -> {owner_force} rows  [owner now bound -> contained]"
        )
        _record(
            f"  FORCE, BYPASSRLS role reads -> {bypass_force} rows  [bypass wins -> LEAKS]"
        )
    finally:
        conn.rollback()  # discard the temp role/table/policy entirely
        conn.close()
