from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests
import logging
import os

app = FastAPI(title="CVE")

import os
import psycopg2
from fastapi import FastAPI, Query, HTTPException

app = FastAPI(title="CVE")

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
      id            SERIAL      PRIMARY KEY,
      cpe_name      TEXT        NOT NULL,
      fetched_at    TIMESTAMP   DEFAULT now(),
      raw_response  JSONB       NOT NULL
    );
    """
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    conn.close()

@app.on_event("startup")
def on_startup():
    try:
        conn = get_db_conn()
        conn.close()
    except Exception as e:
        raise RuntimeError(f"Cannot connect to Postgres: {e}")

    try:
        init_cve_table()
    except Exception as e:
        raise RuntimeError(f"Failed to create cve_lookup table: {e}")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cve_lookup")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = '6e7353ad-70d5-4d73-9ff3-75c589934481'


@app.get("/cves")
def get_cves_by_cpe(
    cpe_name: str = Query(..., alias="cpeName", description="CPE 2.3 URI, e.g. cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
):
    try:
        params = {"cpeName": cpe_name}
        headers = {
            "accept": "application/json",
            "apiKey": NVD_API_KEY
        }

        resp = requests.get(NVD_API_BASE, params=params, headers=headers)
        resp.raise_for_status()
        return resp.json()

    except requests.RequestException as e:
        logger.error(f"Failed to fetch CVEs for {cpe_name}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
