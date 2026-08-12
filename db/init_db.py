"""
Run once to create the schema:

    python -m db.init_db
"""

import pathlib

from db.connection import get_conn

SCHEMA_PATH = pathlib.Path(__file__).parent / "schema.sql"


def main():
    sql = SCHEMA_PATH.read_text()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    print("Schema applied successfully.")


if __name__ == "__main__":
    main()
