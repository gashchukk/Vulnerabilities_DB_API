from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import requests
import logging

app = FastAPI(title="Simple CVE Lookup Service")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple_cve_lookup")

SHODAN_API_BASE = "https://cvedb.shodan.io/cves"


@app.get("/cves")
def get_cves(
    product: str = Query(..., description="Product name to look up (e.g. numpy)")
):
    try:
        params = {
            "product": product,
            "count": "false",
            "is_kev": "false",
            "sort_by_epss": "false",
            "skip": 0,
            "limit": 1000,
        }

        headers = {"accept": "application/json"}
        response = requests.get(SHODAN_API_BASE, params=params, headers=headers)
        response.raise_for_status()

        return response.json()

    except requests.RequestException as e:
        logger.error(f"Failed to fetch CVEs: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
