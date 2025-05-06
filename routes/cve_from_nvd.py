from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
import requests, os
from utils.logger import logger

router = APIRouter()


@router.get("/cve_from_nvd")
def get_cves_by_cpe(
    cpe_name: str = Query(
        ..., alias="cveId", description="CPE 2.3 URI, e.g. CVE-2019-1010218"
    )
):
    try:
        params = {"cveId": cpe_name}
        headers = {
            "accept": "application/json",
            "apiKey": os.getenv("NVD_API_KEY", "YOUR_API_KEY"),
        }

        resp = requests.get(
            os.getenv("NVD_API_BASE"),
            params=params,
            headers=headers,
        )
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

            rows.append(
                {
                    "cve_id": cve_id,
                    "cpe_name": cpe,
                    "fetched_at": fetched_at,
                    "description": desc,
                    "metrics": metrics,
                }
            )

        return rows

    except requests.RequestException as e:
        logger.error(f"Failed to fetch CVEs for {cpe_name}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
