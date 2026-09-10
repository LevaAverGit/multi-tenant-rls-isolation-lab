"""main.py -- a deliberately tiny FastAPI app over the RLS isolation lab.

There is no business logic here on purpose. The app exists only to show the one
thing that matters: it opens a database connection as the non-owner ``app_user``
role, pins the request's tenant via the ``app.tenant_id`` GUC, and queries. The
PostgreSQL Row-Level Security policies (``migrations/002_rls.sql``) do all of the
isolating; the application code stays dumb.

Run it from the project root::

    uvicorn app.main:app --reload

Then, with a real tenant id from the ``tenants`` table::

    curl -H 'X-Tenant-Id: <uuid>' localhost:8000/items
    curl -H 'X-Tenant-Id: <uuid>' localhost:8000/items/unscoped
"""

from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException

from app.db import tenant_connection

app = FastAPI(
    title="multi-tenant-rls-isolation-lab",
    summary="Minimal read API that queries PostgreSQL under a per-request tenant context.",
)

# The single SELECT list shared by both item endpoints. The ONLY difference
# between them is whether they add `WHERE tenant_id = ...` -- which is exactly
# the point being demonstrated.
_ITEM_COLUMNS = "id, tenant_id, name, description, created_at"


def _require_tenant(x_tenant_id: Optional[str]) -> str:
    """Validate the tenant header and return it as a UUID string.

    The app is trusted to set ``app.tenant_id`` to the *authenticated* tenant.
    In this demo the tenant simply arrives in a header; a real system would
    derive it from an authenticated session or token, never from raw input.
    """
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id header is required")
    try:
        # Normalising through UUID() both validates the value and guarantees the
        # GUC we set downstream parses cleanly as `::uuid` inside the policies.
        return str(UUID(x_tenant_id))
    except ValueError:
        raise HTTPException(
            status_code=400, detail="X-Tenant-Id must be a valid UUID"
        )


@app.get("/health")
def health() -> dict:
    """Liveness probe -- does not touch the database."""
    return {"status": "ok"}


@app.get("/items")
def list_items(
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id")
) -> dict:
    """Return the current tenant's items -- the "correct" query.

    This one keeps an explicit ``WHERE tenant_id = ...`` as good hygiene. Note,
    though, that the filter here is belt-and-suspenders: RLS already restricts
    the rows to this tenant, as ``/items/unscoped`` demonstrates.
    """
    tenant_id = _require_tenant(x_tenant_id)
    with tenant_connection(tenant_id) as conn:
        rows = conn.execute(
            f"SELECT {_ITEM_COLUMNS} FROM items "
            "WHERE tenant_id = %s ORDER BY created_at LIMIT 1000",
            (tenant_id,),
        ).fetchall()
    return {"tenant_id": tenant_id, "count": len(rows), "items": rows}


@app.get("/items/unscoped")
def list_items_unscoped(
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id")
) -> dict:
    """THE DEMO ENDPOINT. This query INTENTIONALLY omits ``WHERE tenant_id``.

    In a system without Row-Level Security, ``SELECT * FROM items`` with no
    tenant filter is the classic cross-tenant data leak -- every customer's rows
    come back. Here it still returns only the current tenant's rows, because
    ``FORCE ROW LEVEL SECURITY`` plus the non-owner ``app_user`` role enforce the
    boundary inside the database. The forgotten ``WHERE`` cannot leak data.
    """
    tenant_id = _require_tenant(x_tenant_id)
    with tenant_connection(tenant_id) as conn:
        # No WHERE clause, on purpose -- see the docstring. RLS still isolates.
        # LIMIT is only a resource guard; it is not what scopes the rows.
        rows = conn.execute(
            f"SELECT {_ITEM_COLUMNS} FROM items ORDER BY created_at LIMIT 1000"
        ).fetchall()
    return {"tenant_id": tenant_id, "count": len(rows), "items": rows}
