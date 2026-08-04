"""
PostgreSQL connection helper.

Reads connection settings from environment variables (see .env.example).
Import get_conn() as a context manager anywhere you need a DB connection:

    from db.connection import get_conn
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
"""

import os
from contextlib import contextmanager
from typing import Optional

import psycopg2
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
    "dbname": os.getenv("DB_NAME", "osint_intel"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}


class DatabaseUnavailable(Exception):
    """Raised when the DB can't be reached — callers should degrade gracefully."""


@contextmanager
def get_conn(config: Optional[dict] = None):
    """
    Context manager yielding a psycopg2 connection. Commits on clean exit,
    rolls back on exception, always closes the connection.

    Raises DatabaseUnavailable (not the raw psycopg2 error) so callers in the
    frontend can catch one exception type and fall back to mock data per the
    project's "self-contained data fallback" requirement.
    """
    cfg = config or DB_CONFIG
    try:
        conn = psycopg2.connect(**cfg)
    except psycopg2.OperationalError as e:
        raise DatabaseUnavailable(f"Could not connect to PostgreSQL: {e}") from e

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ping() -> bool:
    """Quick health check — returns True if the DB is reachable."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except DatabaseUnavailable:
        return False
