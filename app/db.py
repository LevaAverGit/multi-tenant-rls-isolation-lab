"""db.py -- the psycopg (v3) data-access layer for the RLS isolation lab.

Its only job is to hand the API a live connection whose *tenant context* is
already pinned, so every statement the request runs is filtered by PostgreSQL
Row-Level Security down to the caller's tenant.

Two design points are what make the isolation real:

  * We connect as ``app_user`` -- a role that is NOT the table owner, NOT a
    superuser, and has ``NOBYPASSRLS``. Any one of those would silently disable
    RLS, so the application must never connect as the bootstrap ``postgres``
    user (that connection exists only as the leak/counter-example in the tests).

  * We set the ``app.tenant_id`` GUC per request as a *transaction-local* value,
    inside an explicit transaction, via ``set_config(..., true)`` (equivalent to
    ``SET LOCAL``) with the tenant id passed as a *bound parameter*. The RLS
    policies read that GUC (see ``migrations/002_rls.sql``).

    Transaction scope is what makes this pattern safe to run behind a connection
    pool. A transaction-local setting is discarded automatically at
    ``COMMIT``/``ROLLBACK``, so a connection handed back to a pool can never carry
    a stale tenant into the next request. Session scope (``set_config(..., false)``)
    does NOT reset on its own: on a pooled connection a request that forgot to
    re-establish its context would silently inherit the previous tenant's rows --
    a cross-tenant leak with no ``WHERE`` and no error. Because the value is
    transaction-local, autocommit must be OFF (a real transaction is required for
    ``SET LOCAL`` to have any effect).

    Scope note: to stay minimal, this module opens one connection per call and
    closes it -- it does NOT ship a pool. The transaction-local design above is
    exactly what lets a real deployment drop in a bounded pool
    (e.g. ``psycopg_pool.ConnectionPool``) without risking tenant bleed; that is
    the property being demonstrated, not a claim that the lab itself pools.
"""

import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

# DEV-ONLY default connection string. The Makefile / environment override this
# through APP_DSN. It deliberately points at the NON-OWNER ``app_user`` role --
# see the module docstring for why that matters.
APP_DSN = os.environ.get(
    "APP_DSN", "postgresql://app_user:app_user@localhost:5432/rls_lab"
)


@contextmanager
def tenant_connection(tenant_id: str) -> Iterator[psycopg.Connection]:
    """Yield a connection with ``app.tenant_id`` pinned to ``tenant_id``.

    The connection is opened with autocommit OFF and the tenant context is set
    *transaction-locally* inside an explicit transaction, so every query the
    caller runs on the yielded connection is transparently scoped to this tenant
    by the RLS policies -- even a query that forgets its ``WHERE`` clause. When
    the ``with`` block exits, the transaction commits (or rolls back on error)
    and the transaction-local ``app.tenant_id`` is discarded, so the connection
    carries no tenant context afterwards. That is what keeps the pattern safe
    behind a connection pool (see the module docstring).

    ``tenant_id`` is bound as a query parameter to ``set_config``, so it can
    never be used for SQL injection; callers are still expected to pass a
    validated UUID string (the API layer validates the request header).
    """
    conn = psycopg.connect(APP_DSN, row_factory=dict_row, connect_timeout=5)  # autocommit off
    try:
        # A real transaction is required for a transaction-local setting to take
        # effect. is_local = true -> the value auto-resets at COMMIT/ROLLBACK, so
        # a pooled connection never leaks a stale tenant into the next request.
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
            # Bound query time so a stalled or lock-blocked backend can't hang a worker.
            conn.execute("SET LOCAL statement_timeout = '5s'")
            yield conn
    finally:
        conn.close()
