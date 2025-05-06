from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from db.connection import get_db_conn
import psycopg2
from utils.logger import logger
import os
import requests
from datetime import datetime
import json

router = APIRouter()


@router.get("/cve_by_keyword")
def get_cves_by_keyword(
    keyword: str = Query(
        ...,
        alias="keywordSearch",
        description="Keyword search for CVEs, e.g. 'Windows MacOs Linux'",
    )
):
    """
    Fetch CVEs by keyword from DB if available, otherwise fetch from NVD API and store in DB.
    """
    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        # Try DB
        cursor.execute(
            """
            SELECT cve_id, cpe_name, fetched_at, description, metrics 
            FROM cve_lookup 
            WHERE description ILIKE %s
        """,
            (f"%{keyword}%",),
        )
        db_results = cursor.fetchall()

        if db_results:
            rows = []
            for row in db_results:
                rows.append(
                    {
                        "cve_id": row[0],
                        "cpe_name": row[1],
                        "fetched_at": (
                            row[2].isoformat()
                            if isinstance(row[2], datetime)
                            else row[2]
                        ),
                        "description": row[3],
                        "metrics": (
                            json.loads(row[4]) if isinstance(row[4], str) else row[4]
                        ),
                    }
                )
            return rows

        # Fetch from NVD API if not found in DB
        params = {"keywordSearch": keyword}
        headers = {"accept": "application/json", "apiKey": os.getenv("NVD_API_KEY")}
        resp = requests.get(os.getenv("NVD_API_BASE"), params=params, headers=headers)
        resp.raise_for_status()

        data = resp.json()
        rows = []
        fetched_at = datetime.utcnow().isoformat()

        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            cve_id = c["id"]
            desc = next(
                (d["value"] for d in c["descriptions"] if d["lang"] == "en"), None
            )
            metrics = (
                c["metrics"]["cvssMetricV2"]
                if "cvssMetricV2" in c["metrics"]
                else c["metrics"]
            )

            cpe = None
            for cfg in c.get("configurations", []):
                for node in cfg.get("nodes", []):
                    match = node.get("cpeMatch", [])
                    if match:
                        cpe = match[0].get("criteria")
                        break
                if cpe:
                    break

            # Insert into DB
            cursor.execute(
                """
                INSERT INTO cve_lookup (cve_id, cpe_name, fetched_at, description, metrics)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO NOTHING
            """,
                (cve_id, cpe, fetched_at, desc, json.dumps(metrics)),
            )

            rows.append(
                {
                    "cve_id": cve_id,
                    "cpe_name": cpe,
                    "fetched_at": fetched_at,
                    "description": desc,
                    "metrics": metrics,
                }
            )

        conn.commit()
        return rows

    except (psycopg2.DatabaseError, requests.RequestException) as e:
        logger.error(f"Error during CVE fetch for keyword '{keyword}': {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

    finally:
        if conn:
            cursor.close()
            conn.close()
