from fastapi import APIRouter, BackgroundTasks
from services.cve_service import fetch_all_chunks

router = APIRouter()


@router.post("/sync_db")
def fetch_all(background_tasks: BackgroundTasks):
    background_tasks.add_task(fetch_all_chunks)
    return {"status": "started", "page_size": 2000}
