from psycopg2.extras import Json
from db.connection import get_db_conn


def store_cve(payload):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_lookup (cve_id, cpe_name, fetched_at, description, metrics)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            payload["cve_id"],
            payload["cpe_name"],
            payload["fetched_at"],
            payload["description"],
            Json(payload["metrics"]),
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
