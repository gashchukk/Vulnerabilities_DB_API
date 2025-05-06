from fastapi import FastAPI
from routes import sync, status, cve_from_nvd, cve_from_db, cve_by_keyword
from db.connection import init_cve_table

app = FastAPI(title="CVE DB")


@app.on_event("startup")
def on_startup():
    init_cve_table()


app.include_router(sync.router)
app.include_router(status.router)
app.include_router(cve_from_nvd.router)
app.include_router(cve_from_db.router)
app.include_router(cve_by_keyword.router)
