import os
import psycopg2

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "test123"),
    "dbname": os.getenv("POSTGRES_DB", "cve_db"),
}


def get_db_conn():
    return psycopg2.connect(**DB_CONFIG)


def init_cve_table():
    sql = """
    CREATE TABLE IF NOT EXISTS cve_lookup (
        cve_id TEXT PRIMARY KEY,
        cpe_name TEXT,
        fetched_at TIMESTAMP NOT NULL DEFAULT now(),
        description TEXT,
        metrics JSONB NOT NULL
    );
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    conn.close()
