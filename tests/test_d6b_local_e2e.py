"""
D6-B focused tests: local filesystem rehydration and case-ID handling.

Scope
-----
1. Reproduce the D6-A empty-after-restart behaviour (rehydration OFF).
2. Assert the D6-B local-only mitigation (rehydration ON) survives a real restart.
3. Case creation, retrieval, detail lookup.
4. '#' case-ID handling: percent-encoded, '#'-stripped alias, URL-safe new IDs.

Everything runs against the real deployed backend (`SentinelAI.api.server`) with
the committed synthetic dataset and simulated LLM mode. Every phase executes in
a separate Python interpreter via `tests/d6b_child.py`, so restart behaviour is
genuinely cross-process.

Run
---
    pip install pytest          # dev-only; deliberately not added to requirements.txt
    python -m pytest tests/test_d6b_local_e2e.py -v -s

No production writes, no live Groq calls, no new public write endpoints.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHILD = REPO_ROOT / "tests" / "d6b_child.py"
RESULT_MARKER = "D6B_RESULT_JSON:"

# Import guard. Importing `SentinelAI.api.server` constructs the module-global
# `repo`, which would create its storage directories relative to the CWD. Some
# tests below import it in-process (resolver unit tests), so point the default
# root at a scratch dir first: importing this module must never touch the tree.
os.environ.setdefault(
    "SENTINELAI_DATA_DIR",
    str(Path(tempfile.gettempdir()) / "d6b-pytest-import-guard"),
)

# Snapshot of the committed artifact directories, taken at import time (i.e.
# before any test runs a pipeline). Used to prove that a run pointed at an
# isolated SENTINELAI_DATA_DIR does not leak artifacts into the working tree.
_ARTIFACT_SUBDIRS = ("cases", "verdicts", "tickets", "emails", "reports")
_REPO_SNAPSHOT = {
    sub: sorted(p.name for p in (REPO_ROOT / "SentinelAI" / sub).glob("*.json"))
    for sub in _ARTIFACT_SUBDIRS
    if (REPO_ROOT / "SentinelAI" / sub).exists()
}


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def child_env_base() -> Dict[str, str]:
    """Environment with serverless + live-LLM disabled, PYTHONPATH pointed at the repo."""
    env = {k: v for k, v in os.environ.items() if k not in ("VERCEL", "GROQ_API_KEY")}
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PYTHONHASHSEED"] = "0"
    return env


def run_child(
    phase: str,
    data_dir: Path,
    rehydrate: str,
    env_base: Dict[str, str],
) -> Dict[str, Any]:
    env = dict(env_base)
    env["SENTINELAI_DATA_DIR"] = str(data_dir)
    env["SENTINELAI_REHYDRATE"] = rehydrate

    proc = subprocess.run(
        [sys.executable, str(CHILD), phase, str(data_dir)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    for line in proc.stdout.splitlines():
        if line.startswith(RESULT_MARKER):
            return json.loads(line[len(RESULT_MARKER):])
    pytest.fail(
        f"child phase '{phase}' produced no result (exit={proc.returncode})\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr[-4000:]}"
    )


@pytest.fixture(scope="session")
def seeded(tmp_path_factory, child_env_base) -> Dict[str, Any]:
    """
    One isolated data dir, seeded once per session by a real child process, then
    re-read by two further child processes (rehydration ON and OFF).

    The seed phase costs ~35 s (the pipeline inspects all 15 detected cases in
    simulated LLM mode), so it is deliberately run only once.
    """
    store = tmp_path_factory.mktemp("d6b_store")
    return {
        "store": store,
        "seed": run_child("seed", store, "1", child_env_base),
        "restart_on": run_child("verify", store, "1", child_env_base),
        "restart_off": run_child("verify", store, "0", child_env_base),
    }


@pytest.fixture(scope="session")
def seeded_store(seeded) -> Path:
    return seeded["store"]


@pytest.fixture(scope="session")
def seed_result(seeded) -> Dict[str, Any]:
    """State as seen by a *fresh* process with rehydration ON (post-D6-B)."""
    return seeded["restart_on"]


@pytest.fixture(scope="session")
def seed_phase_result(seeded) -> Dict[str, Any]:
    """Output of the seeding process itself (creation statuses, HTTP codes)."""
    return seeded["seed"]


@pytest.fixture(scope="session")
def restart_off_result(seeded) -> Dict[str, Any]:
    """Same store, rehydration forced OFF — this is the pre-D6-B behaviour."""
    return seeded["restart_off"]


@pytest.fixture(scope="session")
def collide_result(tmp_path_factory, child_env_base) -> Dict[str, Any]:
    """RC-2 collision behaviour, in its own empty store."""
    store = tmp_path_factory.mktemp("d6b_collide")
    return run_child("collide", store, "1", child_env_base)


@pytest.fixture(scope="session")
def endpoints_result(seeded, child_env_base) -> Dict[str, Any]:
    """Endpoint-compatibility sweep against the seeded store."""
    return run_child("endpoints", seeded["store"], "1", child_env_base)


@pytest.fixture(scope="session")
def security_result(tmp_path_factory, child_env_base) -> Dict[str, Any]:
    """SEC-1 hostile-ID sweep, in its own store with a sibling escape target."""
    base = tmp_path_factory.mktemp("d6b_sec")
    store = base / "store"
    store.mkdir()
    return run_child("security", store, "1", child_env_base)


ENCODED_HOSTILE_IDS = [
    r"'..%2Fescape'",        # percent-encoded traversal
    r"'%2e%2e%2fescape'",    # fully encoded traversal
    r"'..%252fescape'",      # double-encoded traversal
    r"'%23GHOST'",           # percent-encoding ambiguity
]
TRAVERSAL_HOSTILE_IDS = [
    r"'../escape'", r"'../../escape'", r"'....//escape'", r"'a/b'",
    r"'..\\..\\escape'", r"'..'", r"'.'", r"'.hidden'",
]


# ---------------------------------------------------------------------------
# In-process resolver helpers (RC-1)
#
# These exercise DataRepository._resolve directly. HTTP cannot express some of
# the cases: a bare '#' in a path is a URL fragment and never reaches the server.
# ---------------------------------------------------------------------------

def _fraud_case(case_id: str):
    from SentinelAI.models.schemas import FraudCase

    return FraudCase(
        case_id=case_id,
        rule_triggered="Manual-Escalation",
        risk_score=50.0,
        evidence_summary=f"fixture {case_id}",
    )


@pytest.fixture()
def fresh_repo(tmp_path):
    """Factory for an isolated, non-rehydrating DataRepository."""
    from SentinelAI.api.server import DataRepository

    counter = {"n": 0}

    def make(**case_ids):
        counter["n"] += 1
        repo = DataRepository(base_dir=str(tmp_path / f"r{counter['n']}"), rehydrate=False)
        for cid in case_ids.get("ids", []):
            repo.save_case(_fraud_case(cid))
        return repo

    return make


# ---------------------------------------------------------------------------
# 1. Guard rails
# ---------------------------------------------------------------------------

def test_no_live_groq_key_in_child_environment(child_env_base):
    """D6-B must never reach the paid Groq API."""
    assert "GROQ_API_KEY" not in child_env_base


def test_vercel_flag_is_unset_in_child_environment(child_env_base):
    """We exercise the local, non-serverless storage branch."""
    assert "VERCEL" not in child_env_base


# ---------------------------------------------------------------------------
# 2. Empty-after-restart: before (reproduced) vs after (mitigated)
# ---------------------------------------------------------------------------

def test_before_fix_restart_with_rehydration_off_returns_empty(restart_off_result):
    """
    D6-A defect reproduced: a fresh process returns nothing even though the
    storage directory holds valid JSON written by a previous process.
    """
    assert restart_off_result["rehydrate_enabled"] is False
    assert restart_off_result["counts"] == {
        "cases": 0, "verdicts": 0, "tickets": 0, "emails": 0, "reports": 0,
    }


def test_after_fix_restart_with_rehydration_on_returns_records(seed_result):
    """D6-B local-only mitigation: the new process re-reads the directory."""
    counts = seed_result["counts"]
    assert counts["cases"] > 0
    assert counts["verdicts"] > 0
    assert counts["tickets"] > 0
    assert counts["emails"] > 0
    assert counts["reports"] > 0
    assert seed_result["rehydrate_enabled"] is True


def test_rehydration_counts_match_what_the_seed_process_wrote(seed_result):
    """Rehydrated totals must equal the number of persisted records."""
    counts = seed_result["counts"]
    # reports are keyed by date, so one report per distinct day
    assert seed_result["rehydrated_counts"]["cases"] == counts["cases"]
    assert seed_result["rehydrated_counts"]["verdicts"] == counts["verdicts"]
    assert seed_result["rehydrated_counts"]["tickets"] == counts["tickets"]
    assert seed_result["rehydrated_counts"]["emails"] == counts["emails"]


def test_rehydration_not_presented_as_durable_storage():
    """The mitigation is documented as local-only in the module it lives in."""
    source = (REPO_ROOT / "SentinelAI" / "api" / "server.py").read_text(encoding="utf-8")
    assert "LOCAL-ONLY MITIGATION" in source
    assert "NOT PRODUCTION PERSISTENCE" in source


def test_resolution_policy_is_documented_in_the_module():
    """RC-1: the exact-precedence / unambiguous-alias policy must stay documented."""
    source = (REPO_ROOT / "SentinelAI" / "api" / "server.py").read_text(encoding="utf-8")
    assert "RESOLUTION POLICY" in source
    assert "ENCODING NORMALIZATION" in source
    assert "ALIAS" in source
    assert "never re-encode" in source


def test_case_id_collision_policy_is_documented_in_the_module():
    """RC-2: the collision/overwrite policy must stay documented."""
    source = (REPO_ROOT / "SentinelAI" / "api" / "server.py").read_text(encoding="utf-8")
    assert "Case-ID policy" in source
    assert "409 Conflict" in source
    assert "re-drawn" in source


# ---------------------------------------------------------------------------
# 3. Case creation / retrieval / detail lookup
# ---------------------------------------------------------------------------

def test_manual_case_creation_returns_201_and_url_safe_id(seed_phase_result):
    """New auto-generated IDs must not contain '#'.

    '#' is the URL fragment delimiter, so '/api/cases/#XXXX-X' never reaches the
    server; the request degrades to 'GET /api/cases/' -> 200 + the whole list.
    """
    assert seed_phase_result["manual_auto_status"] == 201
    assert seed_phase_result["manual_auto_has_hash"] is False
    assert seed_phase_result["manual_auto_case_id"].startswith("CASE_MANUAL_")


def test_legacy_hash_prefixed_id_is_still_accepted_verbatim(seed_phase_result):
    """Backward compatibility: a caller-supplied '#' ID is accepted unchanged."""
    assert seed_phase_result["manual_legacy_status"] == 201
    assert seed_phase_result["manual_legacy_case_id"] == "#D6B-LEGACY"


def test_created_case_is_retrievable_from_the_list(seed_phase_result, seed_result):
    """Both manual cases survive the round trip and reappear after a restart."""
    assert seed_phase_result["manual_auto_case_id"] in seed_phase_result["case_ids"]
    assert seed_phase_result["manual_legacy_case_id"] in seed_phase_result["case_ids"]
    assert seed_phase_result["manual_auto_case_id"] in seed_result["case_ids"]
    assert seed_phase_result["manual_legacy_case_id"] in seed_result["case_ids"]


def test_detail_lookup_returns_404_for_unknown_case(seed_result):
    assert seed_result["detail"]["missing_case_status"] == 404


def test_linked_records_resolve_for_a_detected_case(seed_result):
    detail = seed_result["detail"]
    assert detail["linked_verdict_status"] == 200
    assert detail["linked_email_status"] == 200
    assert detail["linked_ticket_status"] == 200


def test_pipeline_ran_on_the_committed_dataset(seed_phase_result, seed_result):
    assert seed_phase_result["dataset"] == "SentinelAI/logs/test_stream.jsonl"
    assert seed_phase_result["pipeline_run_status"] == 202
    # deterministic rule mix from the committed 500-row synthetic stream,
    # identical before and after the restart
    assert seed_phase_result["rule_breakdown"] == seed_result["rule_breakdown"]
    assert seed_result["rule_breakdown"] == {
        "Ambiguity-Fixture": 3,          # RC-1 fixtures written straight to storage
        "CROSS_DEVICE_IP_SPIKE": 1,
        "GEO_JURISDICTION_MISMATCH": 11,
        "IMPOSSIBLE_GEO_TRAVEL": 1,
        "Manual-Escalation": 2,
        "VELOCITY_60S_SPIKE": 2,
    }


# ---------------------------------------------------------------------------
# 4. '#' case-ID handling
# ---------------------------------------------------------------------------

def test_hash_case_id_works_when_percent_encoded(seed_result):
    """'%23D6B-LEGACY' must return the single case object."""
    detail = seed_result["detail"]
    assert detail["legacy_encoded_status"] == 200
    assert detail["legacy_encoded_is_object"] is True
    assert detail["legacy_encoded_id_matches"] is True


def test_hash_case_id_resolves_with_hash_stripped(seed_result):
    """Defence in depth: a client that drops the '#' still gets the right case."""
    assert seed_result["detail"]["legacy_stripped_status"] == 200


def test_url_safe_case_id_needs_no_encoding(seed_result):
    """The real fix: new IDs work on the raw path, no percent-encoding needed."""
    detail = seed_result["detail"]
    assert detail["safe_raw_status"] == 200
    assert detail["safe_raw_is_object"] is True
    assert detail["safe_encoded_status"] == 200
    assert detail["safe_encoded_is_object"] is True


def test_unencoded_hash_request_is_a_documented_client_side_limitation(seed_result):
    """
    Pins known behaviour: the URL fragment never leaves the client, so
    'GET /api/cases/#D6B-LEGACY' degrades to 'GET /api/cases/' and FastAPI's
    redirect_slashes returns the full list with HTTP 200. Not fixable
    server-side — hence the URL-safe ID change and the resolver aliases.
    """
    detail = seed_result["detail"]
    assert detail["legacy_raw_status"] == 200
    assert detail["legacy_raw_is_object"] is False


# ---------------------------------------------------------------------------
# 5. Rehydration robustness
# ---------------------------------------------------------------------------

def test_rehydration_skips_corrupt_files_without_failing_startup(tmp_path, child_env_base):
    """One bad artifact must never take the API down at start-up."""
    store = tmp_path / "store"
    (store / "cases").mkdir(parents=True)
    (store / "cases" / "broken.json").write_text("{not json at all", encoding="utf-8")
    (store / "cases" / "wrong_schema.json").write_text('{"nope": 1}', encoding="utf-8")

    result = run_child("verify", store, "1", child_env_base)
    assert result["counts"]["cases"] == 0
    assert result["rehydrate_enabled"] is True


def test_artifacts_are_written_inside_the_configured_storage_root(seeded):
    """
    `TicketGenerator` / `EmailGenerator` / `ReportGenerator` used to resolve their
    own path from os.getenv("VERCEL") and ignore the repository root, so records
    were written somewhere rehydration would never look. They are now routed via
    `repo.*_dir`.
    """
    store: Path = seeded["store"]
    counts = seeded["restart_on"]["counts"]

    for case_id in seeded["restart_on"]["case_ids"]:
        assert (store / "cases" / f"{case_id}.json").exists(), case_id
    assert len(list((store / "verdicts").glob("*.json"))) == counts["verdicts"]
    assert len(list((store / "tickets").glob("*.json"))) == counts["tickets"]
    assert len(list((store / "emails").glob("*.json"))) == counts["emails"]


def test_pipeline_run_does_not_leak_artifacts_into_the_working_tree(seeded):
    """Regression guard: an isolated SENTINELAI_DATA_DIR must keep the repo clean."""
    for sub, before in _REPO_SNAPSHOT.items():
        after = sorted(p.name for p in (REPO_ROOT / "SentinelAI" / sub).glob("*.json"))
        assert after == before, (
            f"pipeline artifacts leaked into SentinelAI/{sub}: "
            f"{sorted(set(after) - set(before))}"
        )


# ---------------------------------------------------------------------------
# 6. RC-1 — case-ID alias resolution
# ---------------------------------------------------------------------------

def test_resolver_exact_match_takes_precedence_over_alias(fresh_repo):
    """
    Requirement: exact IDs always win. With 'ABC' and '#ABC' both stored, each
    lookup must return its own record and never cross the '#' boundary.
    """
    repo = fresh_repo(ids=["ABC", "#ABC"])
    assert repo.resolve_case_id("ABC") == "ABC"
    assert repo.resolve_case_id("#ABC") == "#ABC"
    assert repo.resolve_case_id("%23ABC") == "#ABC"   # '%23ABC' decodes to '#ABC'


def test_resolver_never_returns_a_percent_literal_record(fresh_repo):
    """
    Requirement: ambiguous aliasing must not silently return an unrelated record.
    A record literally named '%23GHOST' is reachable only by its own exact
    (double-encoded) spelling - never by '#GHOST' or 'GHOST'.
    """
    repo = fresh_repo(ids=["%23GHOST"])
    assert repo.resolve_case_id("%2523GHOST") == "%23GHOST"  # decodes to '%23GHOST'
    assert repo.resolve_case_id("#GHOST") is None
    assert repo.resolve_case_id("GHOST") is None


def test_resolver_alias_used_only_when_unambiguous(fresh_repo):
    """Backward compatibility: a lone legacy '#' ID resolves from every spelling."""
    repo = fresh_repo(ids=["#LEGACY-1"])
    assert repo.resolve_case_id("#LEGACY-1") == "#LEGACY-1"
    assert repo.resolve_case_id("LEGACY-1") == "#LEGACY-1"
    assert repo.resolve_case_id("%23LEGACY-1") == "#LEGACY-1"


def test_resolver_returns_none_when_nothing_matches(fresh_repo):
    repo = fresh_repo(ids=["ONLY-ONE"])
    assert repo.resolve_case_id("ONLY-ONE") == "ONLY-ONE"
    assert repo.resolve_case_id("NOPE") is None
    assert repo.resolve_case_id("#NOPE") is None
    assert repo.resolve_case_id("") is None


def test_resolver_is_idempotent_across_repeated_calls(fresh_repo):
    """Resolution must not mutate state or drift between calls."""
    repo = fresh_repo(ids=["ABC", "#ABC"])
    for _ in range(3):
        assert repo.resolve_case_id("ABC") == "ABC"
        assert repo.resolve_case_id("%23ABC") == "#ABC"


def test_http_exact_id_wins_for_the_ambiguous_pair(seed_result):
    """'AMBIG-1' and '#AMBIG-1' coexist on disk (legacy data); exact lookups win."""
    detail = seed_result["detail"]
    assert detail["ambig_plain_status"] == 200
    assert detail["ambig_plain_lookup_id"] == "AMBIG-1"
    assert detail["ambig_encoded_status"] == 200
    assert detail["ambig_encoded_lookup_id"] == "#AMBIG-1"


def test_http_hash_lookup_never_returns_the_percent_literal_record(seed_result):
    """
    Over HTTP: a request whose decoded segment is '#GHOST' must 404 rather than
    silently return the unrelated record literally named '%23GHOST'.
    """
    detail = seed_result["detail"]
    assert detail["ghost_via_hash_status"] == 404
    assert detail["ghost_alias_status"] == 404
    # ...while the literal record is still reachable by its own exact spelling.
    assert detail["ghost_literal_resolves"] == "%23GHOST"


def test_ambiguous_pair_survives_rehydration(seed_result):
    assert "AMBIG-1" in seed_result["case_ids"]
    assert "#AMBIG-1" in seed_result["case_ids"]
    assert "%23GHOST" in seed_result["case_ids"]


# ---------------------------------------------------------------------------
# 7. RC-2 — manual case-ID collisions
# ---------------------------------------------------------------------------

def test_auto_generated_case_id_uses_full_uuid_width(collide_result):
    """122 random bits, not the previous 24-bit fragment."""
    assert collide_result["generated_prefix_ok"] is True
    assert collide_result["generated_hex_only"] is True
    assert collide_result["generated_suffix_len"] == [32]


def test_auto_generated_ids_are_unique_under_volume(collide_result):
    assert collide_result["generated_count"] == 200
    assert collide_result["generated_unique"] == 200


def test_supplied_duplicate_id_is_rejected_not_overwritten(collide_result):
    assert collide_result["first_status"] == 201
    assert collide_result["duplicate_status"] == 409
    # the original record must be untouched
    assert collide_result["stored_after_duplicate_status"] == 200
    assert collide_result["stored_case_id"] == "#DUP-1"
    assert collide_result["stored_risk_score"] == 91.0
    assert collide_result["stored_evidence"] == "original record"


def test_supplied_id_that_alias_collides_is_rejected(collide_result):
    """'DUP-1' aliases '#DUP-1'; creating both would make lookups ambiguous."""
    assert collide_result["alias_collision_status"] == 409


def test_full_width_id_collision_is_not_feasible(collide_result):
    """200 draws from a 122-bit space: zero collisions observed, all well-formed."""
    assert collide_result["generated_all_str"] is True
    assert collide_result["generated_unique"] == collide_result["generated_count"]


# ---------------------------------------------------------------------------
# 9. SEC-1 — caller-supplied case-ID hardening
# ---------------------------------------------------------------------------

def test_every_hostile_case_id_is_rejected_with_422(security_result):
    assert security_result["hostile_all_422"] is True
    assert security_result["hostile_results"], "no hostile IDs were exercised"
    for hostile, status in security_result["hostile_results"].items():
        assert status == 422, f"{hostile} returned {status}, expected 422"


def test_encoded_traversal_variants_are_rejected(security_result):
    """Percent-encoded (and double-encoded) traversal must not slip through."""
    results = security_result["hostile_results"]
    for hostile in ENCODED_HOSTILE_IDS:
        assert hostile in results, f"missing encoded case: {hostile}"
        assert results[hostile] == 422


def test_plain_traversal_and_absolute_paths_are_rejected(security_result):
    results = security_result["hostile_results"]
    for hostile in TRAVERSAL_HOSTILE_IDS:
        assert results.get(hostile) == 422, f"{hostile} -> {results.get(hostile)}"
    absolute = [h for h in results if h.startswith("'/tmp/")]
    assert absolute, "no absolute-path case was exercised"
    assert all(results[h] == 422 for h in absolute)


def test_hostile_submissions_create_no_files(security_result):
    """Nothing written inside the store, and nothing written outside it."""
    assert security_result["case_files_unchanged"] is True
    assert security_result["case_files_after_attacks"] == ["#CANARY.json"]
    assert security_result["escape_dir_untouched"] is True
    assert security_result["escape_files_after"] == []


def test_hostile_submissions_do_not_modify_existing_records(security_result):
    assert security_result["canary_status"] == 201
    assert security_result["canary_after_status"] == 200
    assert security_result["canary_case_id"] == "#CANARY"
    assert security_result["canary_risk_score"] == 77.0
    assert security_result["canary_evidence"] == "canary record"


def test_valid_legacy_and_custom_ids_still_accepted(security_result):
    """Hardening must not break supported legacy IDs or ordinary custom IDs."""
    assert security_result["valid_legacy_status"] == 201
    assert security_result["valid_legacy_case_id"] == "#D6B-LEGACY"
    assert security_result["valid_custom_status"] == 201
    assert security_result["valid_custom_case_id"] == "ABC-123_x"
    assert security_result["valid_auto_status"] == 201
    assert security_result["valid_auto_case_id"].startswith("CASE_MANUAL_")


def test_write_sink_refuses_paths_outside_the_storage_directory(fresh_repo):
    """Defence in depth: the sink itself, independently of endpoint validation."""
    repo = fresh_repo()
    with pytest.raises(ValueError):
        repo._contained_path(repo.cases_dir, "../../escape/x.json")
    with pytest.raises(ValueError):
        repo._contained_path(repo.cases_dir, "/tmp/absolute.json")
    with pytest.raises(ValueError):
        repo._contained_path(repo.cases_dir, "sub/dir/x.json")
    # a legitimate name still resolves inside the directory
    assert repo._contained_path(repo.cases_dir, "#D6B-LEGACY.json").parent == repo.cases_dir.resolve()


def test_save_case_with_unsafe_id_writes_nothing_and_mutates_nothing(fresh_repo):
    """A rejected identifier must not create a file nor alter an existing record."""
    repo = fresh_repo(ids=["#KEEP"])
    before = sorted(p.name for p in repo.cases_dir.glob("*.json"))

    with pytest.raises(ValueError):
        repo.save_case(_fraud_case("../escape"))
    assert "../escape" not in repo.cases
    assert sorted(p.name for p in repo.cases_dir.glob("*.json")) == before
    assert repo.cases["#KEEP"].evidence_summary == "fixture #KEEP"


def test_case_id_validation_policy_is_documented_in_the_module():
    """SEC-1: the allow-list and its rationale must stay documented in code."""
    source = (REPO_ROOT / "SentinelAI" / "api" / "server.py").read_text(encoding="utf-8")
    assert "SEC-1" in source
    assert "validate_new_case_id" in source
    assert "SAFE_NEW_CASE_ID" in source


# ---------------------------------------------------------------------------
# 10. Endpoint compatibility
# ---------------------------------------------------------------------------

def test_all_pre_existing_endpoints_still_respond(endpoints_result):
    assert endpoints_result["statuses"] == {
        "GET /": 200,
        "GET /docs": 200,
        "GET /openapi.json": 200,
        "GET /api/health": 200,
        "GET /api/cases": 200,
        "GET /api/verdicts": 200,
        "GET /api/tickets": 200,
        "GET /api/emails": 200,
        "GET /api/reports": 200,
        "GET /api/reports/latest": 200,
        "GET /api/stats": 200,
        "POST /api/cases": 201,
        "GET /api/v1/stats": 404,   # legacy router still deliberately unmounted
        "GET /ws": 404,             # legacy websocket still deliberately unmounted
    }


def test_openapi_route_surface_is_unchanged(endpoints_result):
    """No route added or removed — in particular no new public write endpoint."""
    assert endpoints_result["openapi_routes"] == [
        "GET /",
        "GET /api/cases",
        "GET /api/cases/{case_id}",
        "GET /api/emails",
        "GET /api/emails/{case_id}",
        "GET /api/health",
        "GET /api/reports",
        "GET /api/reports/latest",
        "GET /api/stats",
        "GET /api/tickets",
        "GET /api/tickets/{ticket_id}",
        "GET /api/verdicts",
        "GET /api/verdicts/{case_id}",
        "POST /api/cases",
        "POST /api/pipeline/run",
        "POST /api/pipeline/stream",
    ]


def test_rehydration_is_off_by_default_under_vercel(tmp_path, child_env_base):
    """
    On Vercel /tmp is per-instance and non-durable; silently rehydrating there
    would fake persistence. Default must be OFF unless explicitly forced on.
    """
    env = dict(child_env_base)
    env["VERCEL"] = "1"
    env["SENTINELAI_DATA_DIR"] = str(tmp_path / "vercel-store")
    env.pop("SENTINELAI_REHYDRATE", None)

    code = (
        "import os,sys; sys.path.insert(0, os.environ['PYTHONPATH']);"
        "from SentinelAI.api.server import repo;"
        "print('D6B_RESULT_JSON:' + __import__('json').dumps("
        "{'rehydrate_enabled': repo.rehydrate_enabled, 'base_dir': str(repo.base_dir)}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=str(REPO_ROOT), env=env,
        capture_output=True, text=True,
    )
    line = next(l for l in proc.stdout.splitlines() if l.startswith(RESULT_MARKER))
    payload = json.loads(line[len(RESULT_MARKER):])
    assert payload["rehydrate_enabled"] is False
    assert payload["base_dir"] == str(tmp_path / "vercel-store")


def test_sentinelai_data_dir_overrides_the_default_storage_root(tmp_path, child_env_base):
    """Local runs must not write into the working tree by default in tests."""
    store = tmp_path / "custom"
    result = run_child("baseline", store, "1", child_env_base)
    assert result["base_dir"] == str(store)
    assert result["counts"]["cases"] == 0
