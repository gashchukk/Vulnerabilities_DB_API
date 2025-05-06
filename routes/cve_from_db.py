from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from db.connection import get_db_conn
import psycopg2
from utils.logger import logger

router = APIRouter()


@router.get("/cve_from_db")
def get_cves_from_db(
    cve_id: str = Query(..., alias="cveId", description="CVE ID, e.g. CVE-2019-1010218")
):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM cve_lookup WHERE cve_id = %s;", (cve_id,))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            return JSONResponse(status_code=404, content={"error": "CVE not found"})

        return [
            {
                "cve_id": row[0],
                "cpe_name": row[1],
                "fetched_at": row[2],
                "description": row[3],
                "metrics": row[4],
            }
            for row in rows
        ]

    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
