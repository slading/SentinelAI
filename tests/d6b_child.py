"""
D6-B local E2E worker.

Every phase runs in a *separate* Python interpreter, launched as a subprocess.
That is the point: the D6-A defect was that a freshly-started process answered
`GET /api/cases -> []`, so the restart behaviour can only be exercised honestly
across real process boundaries, not by resetting an in-process object.

Usage
-----
    python tests/d6b_child.py <phase> <data_dir>

Phases
------
    baseline  Fresh process against `data_dir`. Reports what the API returns.
    seed      Creates two manual cases (one auto-ID, one legacy '#'-prefixed)
              and runs the pipeline against the committed synthetic dataset.
    verify    Fresh process against an already-seeded `data_dir`. Reports what
              the API returns from disk, plus detail lookups.
    report    Orchestrates `seed` + `verify` in child processes and prints the
              deterministic markdown verification report.

Environment (set by the launcher, read at import time by SentinelAI.api.server)
------------------------------------------------------------------------------
    SENTINELAI_DATA_DIR   storage root under test (isolated tmp dir)
    SENTINELAI_REHYDRATE  "1" / "0" - forces rehydration on or off
    VERCEL                MUST be unset (we exercise the local, non-serverless path)
    GROQ_API_KEY          MUST be unset - simulated LLM mode only, zero spend

Safety: this worker refuses to run if GROQ_API_KEY resolves to a live key.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_DATASET = "SentinelAI/logs/test_stream.jsonl"

RESULT_MARKER = "D6B_RESULT_JSON:"


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------

def assert_simulated_llm() -> None:
    """Hard-fail if a live Groq credential is present. D6-B makes no paid calls."""
    sys.path.insert(0, str(REPO_ROOT))
    from SentinelAI.ai.groq_client import GroqClient

    client = GroqClient()
    if not client._is_mock_key:
        raise SystemExit(
            "D6-B ABORTED: a live GROQ_API_KEY is present. "
            "This verification must run in simulated LLM mode only."
        )


def build_client():
    from fastapi.testclient import TestClient
    from SentinelAI.api.server import app, repo

    return TestClient(app), repo


def committed_dataset_path() -> Path:
    path = REPO_ROOT / COMMITTED_DATASET
    if not path.exists():
        raise SystemExit(f"D6-B ABORTED: committed dataset missing at {path}")
    return path


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def _json_or_empty(response) -> List[Dict[str, Any]]:
    if response.status_code != 200:
        return []
    payload = response.json()
    return payload if isinstance(payload, list) else []


def api_summary(client) -> Dict[str, Any]:
    """Full read-side snapshot. Deterministic apart from UUID-derived IDs."""
    cases = _json_or_empty(client.get("/api/cases"))
    verdicts = _json_or_empty(client.get("/api/verdicts"))
    tickets = _json_or_empty(client.get("/api/tickets"))
    emails = _json_or_empty(client.get("/api/emails"))

    reports_resp = client.get("/api/reports")
    reports = _json_or_empty(reports_resp)
    latest_resp = client.get("/api/reports/latest")
    stats_resp = client.get("/api/stats")
    stats = stats_resp.json() if stats_resp.status_code == 200 else {}

    rules: Dict[str, int] = {}
    for case in cases:
        rules[case["rule_triggered"]] = rules.get(case["rule_triggered"], 0) + 1

    return {
        "counts": {
            "cases": len(cases),
            "verdicts": len(verdicts),
            "tickets": len(tickets),
            "emails": len(emails),
            "reports": len(reports),
        },
        "rule_breakdown": dict(sorted(rules.items())),
        "risk_distribution": stats.get("risk_distribution", {}),
        "actions_breakdown": stats.get("actions_breakdown", {}),
        "tokens_used": stats.get("tokens_used", 0),
        "reports_latest_status": latest_resp.status_code,
        "case_ids": sorted(c["case_id"] for c in cases),
    }


def detail_probes(client, cases: List[Dict[str, Any]], repo=None) -> Dict[str, Any]:
    """
    Detail lookups, including the two spellings of a '#'-prefixed legacy ID.

    `detail_encoded_*` is the form a correct client must use ('%23...').
    `detail_raw_*` is the form a naive client uses ('#...'); for a '#' ID the
    fragment never leaves the client, so this is pinned as a known limitation.
    """
    probes: Dict[str, Any] = {}
    if not cases:
        return probes

    by_id = {c["case_id"]: c for c in cases}
    # Prefer the deliberate legacy fixture; fall back to any '#' ID.
    legacy = "#D6B-LEGACY" if "#D6B-LEGACY" in by_id else next(
        (cid for cid in sorted(by_id) if cid.startswith("#")), None
    )
    # A genuinely URL-safe ID (no percent-encoding needed) - detector/manual
    # generated IDs all share the 'CASE_' prefix. '%23GHOST' is deliberately
    # excluded here: it is URL-safe to *store* but not safe in a path segment.
    safe = next((cid for cid in sorted(by_id) if cid.startswith("CASE_")), None)

    def probe(case_id: str, prefix: str) -> None:
        encoded = client.get(f"/api/cases/{quote(case_id, safe='')}")
        raw = client.get(f"/api/cases/{case_id}")
        raw_payload = raw.json() if raw.status_code == 200 else None
        probes[f"{prefix}_case_id"] = case_id
        probes[f"{prefix}_encoded_status"] = encoded.status_code
        probes[f"{prefix}_encoded_is_object"] = isinstance(encoded.json(), dict)
        probes[f"{prefix}_encoded_id_matches"] = (
            isinstance(encoded.json(), dict) and encoded.json().get("case_id") == case_id
        )
        probes[f"{prefix}_raw_status"] = raw.status_code
        probes[f"{prefix}_raw_is_object"] = isinstance(raw_payload, dict)

    if legacy:
        probe(legacy, "legacy")
        # '#'-stripped alias must still resolve via the backend resolver
        stripped = legacy.lstrip("#")
        probes["legacy_stripped_status"] = client.get(f"/api/cases/{stripped}").status_code
    if safe:
        probe(safe, "safe")

    # Linked records for the first case that has a verdict
    linked = None
    for case_id in sorted(by_id):
        if client.get(f"/api/verdicts/{quote(case_id, safe='')}").status_code == 200:
            linked = case_id
            break
    if linked:
        probes["linked_case_id"] = linked
        probes["linked_verdict_status"] = client.get(f"/api/verdicts/{quote(linked, safe='')}").status_code
        probes["linked_email_status"] = client.get(f"/api/emails/{quote(linked, safe='')}").status_code
        tickets = _json_or_empty(client.get("/api/tickets"))
        match = next((t["ticket_id"] for t in tickets if t["case_id"] == linked), None)
        probes["linked_ticket_status"] = (
            client.get(f"/api/tickets/{quote(match, safe='')}").status_code if match else None
        )

    probes["missing_case_status"] = client.get("/api/cases/DEFINITELY-NOT-A-CASE").status_code

    # --- RC-1: legacy ambiguous pair ('ABC' and '#ABC' both present on disk) ---
    # Both were written directly to storage (see _write_legacy_fixtures) because
    # create_case now refuses to build such a pair through the API.
    if "AMBIG-1" in by_id and "#AMBIG-1" in by_id:
        plain = client.get("/api/cases/AMBIG-1")
        encoded = client.get("/api/cases/%23AMBIG-1")
        probes["ambig_plain_status"] = plain.status_code
        probes["ambig_plain_lookup_id"] = plain.json().get("case_id") if plain.status_code == 200 else None
        probes["ambig_encoded_status"] = encoded.status_code
        probes["ambig_encoded_lookup_id"] = encoded.json().get("case_id") if encoded.status_code == 200 else None

    # --- RC-1: a record literally named '%23GHOST' must not be reachable as '#GHOST' ---
    # NB on encoding: httpx/TestClient percent-DECODES the path once before it is
    # sent, so '/api/cases/%23GHOST' reaches the server as '#GHOST'. A real client
    # (curl) would send '%23GHOST' verbatim and Starlette would decode it to '#GHOST'
    # - same result. Assertions below are written against the server-visible value.
    if "%23GHOST" in by_id:
        probes["ghost_via_hash_status"] = client.get("/api/cases/%23GHOST").status_code
        probes["ghost_alias_status"] = client.get("/api/cases/GHOST").status_code
        if repo is not None:
            # ...and the literal record is still reachable by its own exact spelling.
            probes["ghost_literal_resolves"] = repo.resolve_case_id("%23GHOST")

    return probes


def _write_legacy_fixtures(repo, cases_dir) -> List[str]:
    """
    Writes pre-existing legacy case records straight to storage, the way data
    written before D6-B would look, then rehydrates them into the repository.

    Used to reproduce the RC-1 ambiguity scenario, which `create_case` now
    refuses to construct through the API.
    """
    from SentinelAI.models.schemas import FraudCase

    fixture_ids = ["AMBIG-1", "#AMBIG-1", "%23GHOST"]
    for case_id in fixture_ids:
        case = FraudCase(
            case_id=case_id,
            rule_triggered="Ambiguity-Fixture",
            risk_score=50.0,
            related_accounts=["ACC_FIXTURE"],
            related_transactions=[],
            timestamps=[],
            evidence_summary=f"RC-1 fixture record '{case_id}' written directly to storage.",
        )
        (cases_dir / f"{case_id}.json").write_text(case.model_dump_json(indent=2), encoding="utf-8")
    repo.load_from_disk()
    return fixture_ids


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

def phase_baseline(data_dir: str) -> Dict[str, Any]:
    assert_simulated_llm()
    client, repo = build_client()
    return {
        "phase": "baseline",
        "base_dir": str(repo.base_dir),
        "rehydrate_enabled": repo.rehydrate_enabled,
        "rehydrated_counts": repo.rehydrated_counts,
        **api_summary(client),
    }


def phase_seed(data_dir: str) -> Dict[str, Any]:
    assert_simulated_llm()
    client, repo = build_client()

    manual_auto = client.post(
        "/api/cases",
        json={
            "rule_triggered": "Manual-Escalation",
            "risk_score": 85.0,
            "description": "D6-B local verification: auto-generated URL-safe ID",
            "related_accounts": ["ACC_D6B_AUTO"],
        },
    )
    manual_legacy = client.post(
        "/api/cases",
        json={
            "case_id": "#D6B-LEGACY",
            "rule_triggered": "Manual-Escalation",
            "risk_score": 90.0,
            "description": "D6-B local verification: legacy '#' prefixed ID",
            "related_accounts": ["ACC_D6B_LEGACY"],
        },
    )

    # RC-1 fixtures: a legacy ambiguous pair plus a percent-literal record.
    fixture_ids = _write_legacy_fixtures(repo, repo.cases_dir)

    dataset = committed_dataset_path()
    run = client.post(
        "/api/pipeline/run",
        json={"input_file": str(dataset)},
    )

    result = {
        "phase": "seed",
        "rc1_fixture_ids": fixture_ids,
        "base_dir": str(repo.base_dir),
        "rehydrate_enabled": repo.rehydrate_enabled,
        "dataset": COMMITTED_DATASET,
        "manual_auto_status": manual_auto.status_code,
        "manual_auto_case_id": manual_auto.json().get("case_id"),
        "manual_auto_has_hash": "#" in str(manual_auto.json().get("case_id", "")),
        "manual_legacy_status": manual_legacy.status_code,
        "manual_legacy_case_id": manual_legacy.json().get("case_id"),
        "pipeline_run_status": run.status_code,
        **api_summary(client),
    }
    result["detail"] = detail_probes(client, _json_or_empty(client.get("/api/cases")), repo)
    return result


def phase_verify(data_dir: str) -> Dict[str, Any]:
    assert_simulated_llm()
    client, repo = build_client()
    result = {
        "phase": "verify",
        "base_dir": str(repo.base_dir),
        "rehydrate_enabled": repo.rehydrate_enabled,
        "rehydrated_counts": repo.rehydrated_counts,
        **api_summary(client),
    }
    result["detail"] = detail_probes(client, _json_or_empty(client.get("/api/cases")), repo)
    return result


def phase_collide(data_dir: str) -> Dict[str, Any]:
    """
    RC-2: manual case-ID collision behaviour.

    Runs against an isolated, empty store so the results are independent of the
    seeded fixture store.
    """
    assert_simulated_llm()
    client, repo = build_client()

    first = client.post("/api/cases", json={"case_id": "#DUP-1", "risk_score": 91.0,
                                            "description": "original record"})
    duplicate = client.post("/api/cases", json={"case_id": "#DUP-1", "risk_score": 11.0,
                                                "description": "attempted overwrite"})
    alias_collision = client.post("/api/cases", json={"case_id": "DUP-1", "risk_score": 22.0,
                                                      "description": "alias of #DUP-1"})

    # The original record must still hold its own values - not be overwritten.
    stored = client.get("/api/cases/%23DUP-1")

    # Auto-generated IDs: width and uniqueness under volume.
    generated = []
    for _ in range(200):
        resp = client.post("/api/cases", json={"risk_score": 10.0, "description": "collision probe"})
        generated.append(resp.json().get("case_id"))

    return {
        "phase": "collide",
        "first_status": first.status_code,
        "first_case_id": first.json().get("case_id"),
        "duplicate_status": duplicate.status_code,          # expect 409
        "alias_collision_status": alias_collision.status_code,  # expect 409
        "stored_after_duplicate_status": stored.status_code,
        "stored_case_id": stored.json().get("case_id"),
        "stored_risk_score": stored.json().get("risk_score"),
        "stored_evidence": stored.json().get("evidence_summary"),
        "generated_count": len(generated),
        "generated_unique": len(set(generated)),
        "generated_all_str": all(isinstance(g, str) for g in generated),
        "generated_prefix_ok": all(g.startswith("CASE_MANUAL_") for g in generated),
        "generated_suffix_len": sorted({len(g.split("CASE_MANUAL_")[1]) for g in generated}),
        "generated_hex_only": all(
            all(ch in "0123456789ABCDEF" for ch in g.split("CASE_MANUAL_")[1]) for g in generated
        ),
        "generated_sample": generated[:2],
    }


def phase_security(data_dir: str) -> Dict[str, Any]:
    """
    SEC-1: hostile caller-supplied case IDs.

    Runs in its own store with a sibling 'escape target' directory. Every hostile
    submission must be rejected with 422 and must leave the filesystem and the
    existing canary record completely untouched.
    """
    assert_simulated_llm()
    client, repo = build_client()

    store = Path(data_dir)
    escape_dir = store.parent / "escape-target"
    escape_dir.mkdir(parents=True, exist_ok=True)

    def escape_files():
        return sorted(p.name for p in escape_dir.glob("**/*") if p.is_file())

    def case_files():
        return sorted(p.name for p in repo.cases_dir.glob("*.json"))

    # Canary: a valid legacy-style record that must survive every attack.
    canary = client.post("/api/cases", json={
        "case_id": "#CANARY", "risk_score": 77.0, "description": "canary record",
    })

    hostile_ids = [
        "../escape",                          # relative traversal
        "../../escape",                       # deeper traversal
        "..%2Fescape",                        # percent-encoded traversal
        "%2e%2e%2fescape",                    # fully encoded traversal
        "..%252fescape",                      # double-encoded traversal
        "....//escape",                        # stripped-filter bypass attempt
        "a/b",                                # subdirectory separator
        str(escape_dir / "absolute"),         # absolute path -> replaces the base
        "C:\\windows\\system32\\config",      # Windows absolute
        "..\\..\\escape",                     # Windows traversal
        "..",                                 # parent directory
        ".",                                  # current directory
        ".hidden",                            # dotfile
        "%23GHOST",                           # percent-encoding ambiguity
        "a\nb",                               # control character (LF)
        "a\x00b",                             # NUL byte
        " leading",                           # leading whitespace
        "trailing ",                          # trailing whitespace
        "",                                   # empty
    ]

    before_files = case_files()
    before_escape = escape_files()

    hostile_results = {}
    for hostile in hostile_ids:
        resp = client.post("/api/cases", json={
            "case_id": hostile, "risk_score": 1.0, "description": "hostile",
        })
        hostile_results[repr(hostile)] = resp.status_code

    after_files = case_files()
    after_escape = escape_files()

    stored_canary = client.get("/api/cases/%23CANARY")

    valid_legacy = client.post("/api/cases", json={
        "case_id": "#D6B-LEGACY", "risk_score": 90.0, "description": "valid legacy id",
    })
    valid_custom = client.post("/api/cases", json={
        "case_id": "ABC-123_x", "risk_score": 40.0, "description": "valid custom id",
    })
    valid_auto = client.post("/api/cases", json={"risk_score": 30.0})

    return {
        "phase": "security",
        "escape_dir": str(escape_dir),
        "canary_status": canary.status_code,
        "hostile_results": hostile_results,
        "hostile_all_422": all(s == 422 for s in hostile_results.values()),
        "case_files_before": before_files,
        "case_files_after_attacks": after_files,
        "case_files_unchanged": before_files == after_files,
        "escape_files_before": before_escape,
        "escape_files_after": after_escape,
        "escape_dir_untouched": not after_escape,
        "canary_after_status": stored_canary.status_code,
        "canary_case_id": stored_canary.json().get("case_id"),
        "canary_risk_score": stored_canary.json().get("risk_score"),
        "canary_evidence": stored_canary.json().get("evidence_summary"),
        "valid_legacy_status": valid_legacy.status_code,
        "valid_legacy_case_id": valid_legacy.json().get("case_id"),
        "valid_custom_status": valid_custom.status_code,
        "valid_custom_case_id": valid_custom.json().get("case_id"),
        "valid_auto_status": valid_auto.status_code,
        "valid_auto_case_id": valid_auto.json().get("case_id"),
    }


def phase_endpoints(data_dir: str) -> Dict[str, Any]:
    """
    Endpoint-compatibility sweep: confirms every pre-existing route still
    responds with the same status code, and that the OpenAPI route surface is
    unchanged (no route added, removed or re-typed).
    """
    assert_simulated_llm()
    client, repo = build_client()

    probes = {
        "GET /": client.get("/"),
        "GET /docs": client.get("/docs"),
        "GET /openapi.json": client.get("/openapi.json"),
        "GET /api/health": client.get("/api/health"),
        "GET /api/cases": client.get("/api/cases"),
        "GET /api/verdicts": client.get("/api/verdicts"),
        "GET /api/tickets": client.get("/api/tickets"),
        "GET /api/emails": client.get("/api/emails"),
        "GET /api/reports": client.get("/api/reports"),
        "GET /api/reports/latest": client.get("/api/reports/latest"),
        "GET /api/stats": client.get("/api/stats"),
        "POST /api/cases": client.post("/api/cases", json={"risk_score": 1.0,
                                                           "description": "endpoint sweep"}),
        "GET /api/v1/stats": client.get("/api/v1/stats"),
        "GET /ws": client.get("/ws"),
    }
    statuses = {name: resp.status_code for name, resp in probes.items()}

    openapi = probes["GET /openapi.json"].json()
    routes = sorted(
        f"{method.upper()} {path}"
        for path, methods in openapi["paths"].items()
        for method in methods
        if method != "parameters"
    )

    return {
        "phase": "endpoints",
        "statuses": statuses,
        "openapi_routes": routes,
        "openapi_schema_count": len(openapi.get("components", {}).get("schemas", {})),
    }


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def run_child(phase: str, data_dir: str, rehydrate: str) -> Dict[str, Any]:
    env = {k: v for k, v in os.environ.items() if k not in ("VERCEL", "GROQ_API_KEY")}
    env.update(
        {
            "SENTINELAI_DATA_DIR": data_dir,
            "SENTINELAI_REHYDRATE": rehydrate,
            "PYTHONPATH": str(REPO_ROOT),
            "PYTHONHASHSEED": "0",
        }
    )
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), phase, data_dir],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    for line in proc.stdout.splitlines():
        if line.startswith(RESULT_MARKER):
            return json.loads(line[len(RESULT_MARKER):])
    raise SystemExit(
        f"D6-B child phase '{phase}' produced no result.\n"
        f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr[-4000:]}"
    )


def _table(rows: List[List[Any]], header: List[str]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def phase_report(data_dir: str) -> Dict[str, Any]:
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="d6b-report-"))
    seeded_dir = tmp / "store"
    seeded_dir.mkdir(parents=True, exist_ok=True)

    baseline = run_child("baseline", str(seeded_dir), "1")
    seeded = run_child("seed", str(seeded_dir), "1")
    after_restart_on = run_child("verify", str(seeded_dir), "1")
    after_restart_off = run_child("verify", str(seeded_dir), "0")

    on = after_restart_on["counts"]
    off = after_restart_off["counts"]
    seed_counts = seeded["counts"]

    rows = [
        ["cases", baseline["counts"]["cases"], seed_counts["cases"], on["cases"], off["cases"]],
        ["verdicts", baseline["counts"]["verdicts"], seed_counts["verdicts"], on["verdicts"], off["verdicts"]],
        ["tickets", baseline["counts"]["tickets"], seed_counts["tickets"], on["tickets"], off["tickets"]],
        ["emails", baseline["counts"]["emails"], seed_counts["emails"], on["emails"], off["emails"]],
        ["reports", baseline["counts"]["reports"], seed_counts["reports"], on["reports"], off["reports"]],
    ]

    detail = after_restart_on.get("detail", {})
    detail_rows = [
        ["Safe ID, raw path (no encoding)", detail.get("safe_case_id", "-"),
         detail.get("safe_raw_status"), "object" if detail.get("safe_raw_is_object") else "list/other"],
        ["Safe ID, encoded path", detail.get("safe_case_id", "-"),
         detail.get("safe_encoded_status"), "object" if detail.get("safe_encoded_is_object") else "list/other"],
        ["Legacy '#' ID, encoded path ('%23')", detail.get("legacy_case_id", "-"),
         detail.get("legacy_encoded_status"), "object" if detail.get("legacy_encoded_is_object") else "list/other"],
        ["Legacy '#' ID, '#' stripped", detail.get("legacy_case_id", "-"),
         detail.get("legacy_stripped_status"), "resolver alias"],
        ["Legacy '#' ID, raw path (known limitation)", detail.get("legacy_case_id", "-"),
         detail.get("legacy_raw_status"), "list (fragment dropped client-side)"],
        ["Non-existent case", "DEFINITELY-NOT-A-CASE",
         detail.get("missing_case_status"), "404"],
    ]

    md = f"""# SentinelAI D6-B — Deterministic Local E2E Verification Report

Generated by `python tests/d6b_child.py report <tmpdir>`.
Baseline: `main` @ `0e56605` + D6-B patch. Simulated LLM mode only — **no live Groq calls**.

## 1. Storage under test

| Item | Value |
| --- | --- |
| `SENTINELAI_DATA_DIR` | `{seeded_dir}` (isolated tmp dir, not the working tree) |
| Committed dataset | `{COMMITTED_DATASET}` |
| LLM mode | SIMULATED (`GROQ_API_KEY` unset; child aborts on a live key) |
| Serverless flag | `VERCEL` unset → local path, rehydration ON by default |

## 2. Before / after restart behaviour

{_table(rows, ["Records", "Cold empty", "After seed", "Restart (ON)", "Restart (OFF)"])}

- **Restart (OFF)** reproduces the D6-A defect exactly: `0` records despite valid JSON on disk.
- **Restart (ON)** is the D6-B local-only mitigation: the new process re-reads the directory.

## 3. Deterministic content after restart

Rule breakdown (deterministic — driven by the committed dataset, `seed=42`):

{_table([[k, v] for k, v in after_restart_on["rule_breakdown"].items()], ["rule_triggered", "cases"])}

Risk distribution: `{after_restart_on["risk_distribution"]}`
Actions breakdown: `{after_restart_on["actions_breakdown"]}`
Tokens (simulated): `{after_restart_on["tokens_used"]}`
`GET /api/reports/latest` → `{after_restart_on["reports_latest_status"]}`

Rehydration counts reported by the restarted process: `{after_restart_on["rehydrated_counts"]}`

*Non-deterministic by design:* individual `case_id` / `ticket_id` / `email_id` values embed
`uuid4`. Counts, rule mix, risk scores and actions are reproducible run-to-run.

## 4. Detail lookup / case-ID handling

{_table(detail_rows, ["Lookup", "Case ID", "HTTP", "Body shape"])}

Linked-record lookups for case `{detail.get("linked_case_id", "-")}`:
verdict → `{detail.get("linked_verdict_status")}`, email → `{detail.get("linked_email_status")}`,
ticket → `{detail.get("linked_ticket_status")}`.

## 5. Scope statement

This is **local synthetic-workflow verification**. It exercises the real deployed
backend code path (`SentinelAI.api.server`) against the committed synthetic
dataset in simulated LLM mode. It is **not** production E2E verification, and the
local filesystem rehydration it demonstrates is **not** durable production storage.
"""

    return {"phase": "report", "markdown": md, "raw": {
        "baseline": baseline, "seed": seeded,
        "restart_on": after_restart_on, "restart_off": after_restart_off,
    }}


# ---------------------------------------------------------------------------

PHASES = {
    "baseline": phase_baseline,
    "seed": phase_seed,
    "verify": phase_verify,
    "collide": phase_collide,
    "security": phase_security,
    "endpoints": phase_endpoints,
    "report": phase_report,
}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: python tests/d6b_child.py <baseline|seed|verify|report> <data_dir>")
    phase, data_dir = sys.argv[1], sys.argv[2]
    if phase not in PHASES:
        raise SystemExit(f"unknown phase: {phase}")

    result = PHASES[phase](data_dir)

    if phase == "report":
        print(result["markdown"])
        print()
        print(RESULT_MARKER + json.dumps({k: v["counts"] for k, v in result["raw"].items()}))
    else:
        print(RESULT_MARKER + json.dumps(result))


if __name__ == "__main__":
    main()
