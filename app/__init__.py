"""Minimal application layer for the RLS isolation lab.

`db` manages the psycopg (v3) connection and pins the per-request tenant GUC;
`main` is a tiny FastAPI app whose only job is to query under that tenant
context so the PostgreSQL Row-Level Security policies can do the isolating.
"""
