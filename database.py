from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import JSONResponse
import requests, logging, os, psycopg2, json
from datetime import datetime
from fastapi import Query
from psycopg2.extras import Json

app = FastAPI(title="CVE DB")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cve_bulk")

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
      cve_id        TEXT      PRIMARY KEY,
      cpe_name      TEXT,      
      fetched_at    TIMESTAMP   NOT NULL DEFAULT now(),
      description   TEXT,
      metrics       JSONB      NOT NULL,
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
    init_cve_table()


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "YOUR_API_KEY")
PAGE_SIZE = 2000


def store_page(payload):
    """Insert one page of results as a JSONB blob."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_lookup (cve_id, cpe_name, fetched_at, description, metrics, raw_response)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            payload["cve_id"],
            payload["cpe_name"],
            payload["fetched_at"],
            payload["description"],
            Json(payload["metrics"]),
            Json(payload["raw_response"]),
        ),
    )

    conn.commit()
    cur.close()
    conn.close()


def fetch_all_chunks():
    """Fetch all CVEs in pages of PAGE_SIZE and store each page."""
    start = 0
    total = None

    while True:
        params = {"startIndex": start, "resultsPerPage": PAGE_SIZE}
        headers = {"accept": "application/json", "apiKey": NVD_API_KEY}

        logger.info(f"Fetching CVEs {start}–{start+PAGE_SIZE}…")
        resp = requests.get(NVD_API_BASE, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        if total is None:
            total = data.get("totalResults", 0)
            print("Total CVEs: ", total)
            logger.info(f"Total CVEs to fetch: {total}")

        fetched_at = data["timestamp"]
        for item in data["vulnerabilities"]:
            c = item["cve"]
            cve_id = c["id"]
            desc = next(
                (d["value"] for d in c["descriptions"] if d["lang"] == "en"), None
            )
            metics = c["metrics"]

            cpe = None
            for cfg in c.get("configurations", []):
                for node in cfg.get("nodes", []):
                    match = node.get("cpeMatch", [])
                    if match:
                        cpe = match[0].get("criteria")
                        break
                if cpe:
                    break
            print("Storing: ", cve_id)
            store_page(
                {
                    "cve_id": cve_id,
                    "cpe_name": cpe,
                    "fetched_at": fetched_at,
                    "description": desc,
                    "metrics": metics,
                    "raw_response": json.dumps(item),
                }
            )

        logger.info(f"Stored chunk starting at {start}")

        start += PAGE_SIZE
        if start >= total:
            break


@app.post("/fetch_all")
def fetch_all(background_tasks: BackgroundTasks):
    """
    Triggers a full, paginated download of the NVD CVE dataset.
    Each page is saved in `cve_lookup.raw_response`.
    """
    background_tasks.add_task(fetch_all_chunks)
    return {"status": "started", "page_size": PAGE_SIZE}


@app.get("/status")
def status():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cve_lookup;")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return {"pages_stored": count}


@app.get("/cve_by_id")
def get_cves_by_cpe(
    cpe_name: str = Query(
        ..., alias="cveId", description="CPE 2.3 URI, e.g. CVE-2019-1010218"
    )
):
    try:
        params = {"cveId": cpe_name}
        headers = {"accept": "application/json", "apiKey": NVD_API_KEY}

        resp = requests.get(NVD_API_BASE, params=params, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        rows = []
        fetched_at = data["timestamp"]
        for item in data["vulnerabilities"]:
            c = item["cve"]
            cve_id = c["id"]
            desc = next(
                (d["value"] for d in c["descriptions"] if d["lang"] == "en"), None
            )
            metics = c["metrics"]

            cpe = None
            for cfg in c.get("configurations", []):
                for node in cfg.get("nodes", []):
                    match = node.get("cpeMatch", [])
                    if match:
                        cpe = match[0].get("criteria")
                        break
                if cpe:
                    break

            rows.append(
                {
                    "cve_id": cve_id,
                    "cpe_name": cpe,
                    "fetched_at": fetched_at,
                    "description": desc,
                    "metrics": metics,
                    "raw_response": json.dumps(item),
                }
            )

        return rows

    except requests.RequestException as e:
        logger.error(f"Failed to fetch CVEs for {cpe_name}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
