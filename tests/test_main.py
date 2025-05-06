import pytest
from fastapi.testclient import TestClient
from main import app  

client = TestClient(app)

def test_status_endpoint():
    response = client.get("/status")
    assert response.status_code == 200
    assert "count" in response.json()

def test_cve_from_nvd_real():
    response = client.get("/cve_from_nvd", params={"cve_id": "CVE-2021-34527"})
    assert response.status_code == 200
    assert "cve_id" in response.json()
    assert response.json()["cve_id"] == "CVE-2021-34527"