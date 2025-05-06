from fastapi import APIRouter
from db.connection import get_db_conn

router = APIRouter()


@router.get("/status")
def status():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cve_lookup;")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return {"pages_stored": count}
