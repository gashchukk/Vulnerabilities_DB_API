import requests
from utils.logger import logger
from models.cve_model import store_cve
import os

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "YOUR_API_KEY")
PAGE_SIZE = 2000


def fetch_all_chunks():
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
            logger.info(f"Total CVEs to fetch: {total}")

        fetched_at = data["timestamp"]
        for item in data["vulnerabilities"]:
            c = item["cve"]
            cve_id = c["id"]
            desc = next(
                (d["value"] for d in c["descriptions"] if d["lang"] == "en"), None
            )
            metrics = c["metrics"]

            cpe = None
            for cfg in c.get("configurations", []):
                for node in cfg.get("nodes", []):
                    match = node.get("cpeMatch", [])
                    if match:
                        cpe = match[0].get("criteria")
                        break
                if cpe:
                    break

            store_cve(
                {
                    "cve_id": cve_id,
                    "cpe_name": cpe,
                    "fetched_at": fetched_at,
                    "description": desc,
                    "metrics": metrics,
                }
            )

        logger.info(f"Stored chunk starting at {start}")
        start += PAGE_SIZE
        if start >= total:
            break
