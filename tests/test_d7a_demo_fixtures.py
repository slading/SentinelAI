import os
import sys
import json
import subprocess
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

@pytest.fixture(scope="module")
def vercel_sim():
    """
    Spawns a clean subprocess to simulate the Vercel production environment.
    This prevents the test suite from globally polluting `os.environ["VERCEL"]`
    or instantiating the FastAPI app with test overrides in the main process.
    """
    script = """
import json
from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)
results = {}

# 1. Privileged Endpoints
results["post_cases"] = client.post("/api/cases", json={"case_id": "TEST", "rule_triggered": "TEST", "risk_score": 50, "description": "TEST"}).status_code
results["post_run"] = client.post("/api/pipeline/run").status_code
results["post_stream"] = client.post("/api/pipeline/stream").status_code

# 2. GET Collections
results["cases"] = {"status": client.get("/api/cases").status_code, "data": client.get("/api/cases").json()}
results["tickets"] = {"status": client.get("/api/tickets").status_code, "data": client.get("/api/tickets").json()}

# 3. GET Details
results["case_details"] = {}
results["verdicts"] = {}
results["emails"] = {}
for c in results["cases"]["data"]:
    cid = c.get("case_id")
    results["case_details"][cid] = {"status": client.get(f"/api/cases/{cid}").status_code, "data": client.get(f"/api/cases/{cid}").json()}
    results["verdicts"][cid] = {"status": client.get(f"/api/verdicts/{cid}").status_code, "data": client.get(f"/api/verdicts/{cid}").json()}
    results["emails"][cid] = {"status": client.get(f"/api/emails/{cid}").status_code, "data": client.get(f"/api/emails/{cid}").json()}

results["ticket_details"] = {}
for t in results["tickets"]["data"]:
    tid = t.get("ticket_id")
    results["ticket_details"][tid] = {"status": client.get(f"/api/tickets/{tid}").status_code, "data": client.get(f"/api/tickets/{tid}").json()}

# 4. Reports and Stats
results["report"] = {"status": client.get("/api/reports/latest").status_code, "data": client.get("/api/reports/latest").json()}
results["stats"] = {"status": client.get("/api/stats").status_code, "data": client.get("/api/stats").json()}

print("D7A_RESULT:" + json.dumps(results))
"""
    env = os.environ.copy()
    env["VERCEL"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT)

    proc = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Subprocess failed:\\nSTDOUT:\\n{proc.stdout}\\nSTDERR:\\n{proc.stderr}")

    for line in proc.stdout.splitlines():
        if line.startswith("D7A_RESULT:"):
            return json.loads(line[11:])

    raise RuntimeError("No D7A_RESULT found in subprocess output.")


def test_privileged_endpoints_return_404_in_vercel_mode(vercel_sim):
    """
    Ensure that under Vercel production mode, mutation endpoints return 404
    due to the require_privileged_api_key dependency, isolating from real Groq.
    """
    assert vercel_sim["post_cases"] == 404
    assert vercel_sim["post_run"] == 404
    assert vercel_sim["post_stream"] == 404


def test_demo_fixture_loading_and_get_integrity(vercel_sim):
    """
    Verify that exactly 4 cases, and all linked fixtures load correctly.
    """
    assert vercel_sim["cases"]["status"] == 200
    cases = vercel_sim["cases"]["data"]
    assert len(cases) == 4, "Expected exactly 4 synthetic demo cases"

    case_ids = [c["case_id"] for c in cases]

    # Check details, verdicts, emails
    for cid in case_ids:
        assert vercel_sim["case_details"][cid]["status"] == 200
        assert vercel_sim["case_details"][cid]["data"]["case_id"] == cid

        assert vercel_sim["verdicts"][cid]["status"] == 200
        assert vercel_sim["verdicts"][cid]["data"]["case_id"] == cid

        assert vercel_sim["emails"][cid]["status"] == 200
        assert vercel_sim["emails"][cid]["data"]["case_id"] == cid

    # Tickets
    assert vercel_sim["tickets"]["status"] == 200
    tickets = vercel_sim["tickets"]["data"]
    assert len(tickets) == 4, "Expected exactly 4 tickets"

    # Verify tickets reference correct cases
    for t in tickets:
        tid = t["ticket_id"]
        assert vercel_sim["ticket_details"][tid]["status"] == 200
        assert t["case_id"] in case_ids, f"Ticket {tid} references unknown case {t['case_id']}"

    # Report
    assert vercel_sim["report"]["status"] == 200
    report = vercel_sim["report"]["data"]
    assert report["total_cases"] == 4

    # Stats
    assert vercel_sim["stats"]["status"] == 200
    stats = vercel_sim["stats"]["data"]
    assert stats["total_cases"] == 4


def test_seventeen_fixtures_loaded(vercel_sim):
    """
    Verify the strict D7-A scope: exactly 17 read-only fixtures were loaded.
    """
    cases_count = len(vercel_sim["cases"]["data"])
    verdicts_count = len(vercel_sim["verdicts"])
    emails_count = len(vercel_sim["emails"])
    tickets_count = len(vercel_sim["tickets"]["data"])
    reports_count = 1 if vercel_sim["report"]["status"] == 200 else 0
    total = cases_count + verdicts_count + emails_count + tickets_count + reports_count

    assert total == 17, f"Expected 17 total loaded fixtures, got {total}"
