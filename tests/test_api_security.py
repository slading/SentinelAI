"""D6-C2 security regression tests for the public FastAPI application.

All tests use temporary storage, an explicit local test key, and mock LLM mode.
No test instantiates the real Groq SDK client or sends an external request.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable

import pytest
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient


TEST_API_KEY = secrets.token_urlsafe(32)
REPO_ROOT = Path(__file__).resolve().parent.parent

# Importing the app creates the process-global repository. Keep that import
# guarded even if another test module imports the app before this module's fixture.
os.environ.setdefault(
    "SENTINELAI_DATA_DIR",
    str(Path(tempfile.gettempdir()) / "d6c2-pytest-import-guard"),
)


@pytest.fixture()
def api_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SENTINELAI_DATA_DIR", str(tmp_path / "import-store"))
    monkeypatch.setenv("SENTINELAI_CORS_ORIGINS", "")
    monkeypatch.setenv("SENTINELAI_LLM_MODE", "mock")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_MODE", "disabled")
    monkeypatch.delenv("SENTINELAI_PRIVILEGED_API_KEY", raising=False)

    server = importlib.import_module("SentinelAI.api.server")
    previous_repo = server.repo
    isolated_repo = server.DataRepository(base_dir=str(tmp_path / "records"), rehydrate=False)
    server.repo = isolated_repo

    try:
        with TestClient(server.app) as client:
            yield server, client, isolated_repo, tmp_path
    finally:
        server.repo = previous_repo


def _privileged_requests(client: TestClient, input_file: str = "SentinelAI/logs/test_stream.jsonl"):
    return [
        client.post("/api/cases", json={"risk_score": 12.0, "description": "auth test"}),
        client.post("/api/pipeline/run", json={"input_file": input_file}),
        client.post("/api/pipeline/stream", json={"input_file": input_file}),
    ]


def _repo_snapshot(repo) -> Dict[str, Any]:
    return {
        "cases": dict(repo.cases),
        "verdicts": dict(repo.verdicts),
        "tickets": dict(repo.tickets),
        "emails": dict(repo.emails),
        "reports": dict(repo.reports),
        "files": {
            name: sorted(path.name for path in getattr(repo, f"{name}_dir").glob("*.json"))
            for name in ("cases", "verdicts", "tickets", "emails", "reports")
        },
    }


def _private_mode(monkeypatch: pytest.MonkeyPatch, *, key: str = TEST_API_KEY) -> None:
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_MODE", "api_key")
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_API_KEY", key)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)


def test_all_privileged_posts_are_denied_by_default_before_work(api_context, monkeypatch):
    server, client, repo, _ = api_context
    scheduled = []
    llm_inits = []
    synthetic_inits = []

    monkeypatch.setattr(server, "execute_pipeline_task", lambda *args: scheduled.append(args))
    monkeypatch.setattr(server, "LLMInspector", lambda *args, **kwargs: llm_inits.append(True))
    monkeypatch.setattr(
        server,
        "FintechDataGenerator",
        lambda *args, **kwargs: synthetic_inits.append(True),
    )
    before = _repo_snapshot(repo)

    responses = _privileged_requests(client)
    no_body_responses = [
        client.post("/api/cases"),
        client.post("/api/pipeline/run"),
        client.post("/api/pipeline/stream"),
    ]

    assert [response.status_code for response in responses] == [404, 404, 404]
    assert [response.status_code for response in no_body_responses] == [404, 404, 404]
    assert scheduled == []
    assert llm_inits == []
    assert synthetic_inits == []
    assert _repo_snapshot(repo) == before


def test_missing_and_invalid_credentials_are_identical_for_all_posts(api_context, monkeypatch):
    server, client, repo, _ = api_context
    _private_mode(monkeypatch)
    before = _repo_snapshot(repo)

    missing = _privileged_requests(client)
    invalid = [
        client.post("/api/cases", json={"risk_score": 12.0}, headers={"X-API-Key": "wrong"}),
        client.post(
            "/api/pipeline/run",
            json={"input_file": "SentinelAI/logs/test_stream.jsonl"},
            headers={"X-API-Key": "wrong"},
        ),
        client.post(
            "/api/pipeline/stream",
            json={"input_file": "SentinelAI/logs/test_stream.jsonl"},
            headers={"X-API-Key": "wrong"},
        ),
    ]

    assert [response.status_code for response in missing] == [401, 401, 401]
    assert [response.status_code for response in invalid] == [401, 401, 401]
    assert [response.json() for response in missing] == [response.json() for response in invalid]
    assert all(response.json() == {"detail": "Unauthorized"} for response in missing)
    assert _repo_snapshot(repo) == before


def test_api_key_mode_with_missing_server_secret_fails_closed(api_context, monkeypatch):
    _, client, repo, _ = api_context
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_MODE", "api_key")
    monkeypatch.delenv("SENTINELAI_PRIVILEGED_API_KEY", raising=False)
    before = _repo_snapshot(repo)

    response = client.post("/api/cases", json={"risk_score": 10.0}, headers={"X-API-Key": TEST_API_KEY})

    assert response.status_code == 503
    assert _repo_snapshot(repo) == before


def test_production_and_vercel_always_deny_private_mode(api_context, monkeypatch):
    _, client, repo, _ = api_context
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_MODE", "api_key")
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_API_KEY", TEST_API_KEY)
    before = _repo_snapshot(repo)

    monkeypatch.delenv("ENVIRONMENT", raising=False)
    unspecified_environment_responses = _privileged_requests(client)
    monkeypatch.setenv("ENVIRONMENT", "production")
    production_responses = _privileged_requests(client)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("VERCEL", "1")
    vercel_responses = _privileged_requests(client)

    assert [response.status_code for response in unspecified_environment_responses] == [404, 404, 404]
    assert [response.status_code for response in production_responses] == [404, 404, 404]
    assert [response.status_code for response in vercel_responses] == [404, 404, 404]
    assert _repo_snapshot(repo) == before


@pytest.mark.parametrize(
    ("marker", "value"),
    [
        ("ENVIRONMENT", "prod"),
        ("ENVIRONMENT", " Production "),
        ("ENVIRONMENT", "staging"),
        ("VERCEL_ENV", "production"),
        ("VERCEL_ENV", "preview"),
        ("VERCEL", "1"),
        ("VERCEL", "TRUE"),
        ("VERCEL", "yes"),
        ("VERCEL", "on"),
    ],
)
def test_deployment_markers_cannot_enable_private_routes(api_context, monkeypatch, marker, value):
    _, client, _, _ = api_context
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_MODE", "api_key")
    monkeypatch.setenv("SENTINELAI_PRIVILEGED_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv(marker, value)

    responses = _privileged_requests(client)

    assert [response.status_code for response in responses] == [404, 404, 404]


def test_valid_private_key_is_limited_to_nonproduction_local_mode(api_context, monkeypatch):
    server, client, repo, tmp_path = api_context
    _private_mode(monkeypatch)
    headers = {"X-API-Key": TEST_API_KEY}

    case_response = client.post(
        "/api/cases",
        json={"case_id": "D6C2-LOCAL", "risk_score": 25.0, "description": "isolated test"},
        headers=headers,
    )
    assert case_response.status_code == 201
    assert repo.resolve_case_id("D6C2-LOCAL") == "D6C2-LOCAL"
    assert (repo.cases_dir / "D6C2-LOCAL.json").is_file()

    scheduled = []
    monkeypatch.setattr(server, "execute_pipeline_task", lambda *args: scheduled.append(args))
    run_response = client.post(
        "/api/pipeline/run",
        json={"input_file": "SentinelAI/logs/test_stream.jsonl"},
        headers=headers,
    )
    assert run_response.status_code == 202
    assert len(scheduled) == 1
    assert scheduled[0][1] == str((REPO_ROOT / "SentinelAI/logs/test_stream.jsonl").resolve())

    # Exercise the mounted stream route with local stubs only. No Groq client is
    # constructed and no external request is possible in this test.
    class FakeGenerator:
        def __init__(self, **kwargs):
            pass

        def generate_stream(self):
            return []

    class FakeDetector:
        def __init__(self, **kwargs):
            pass

        def detect_all(self, dataframe):
            return []

    class FakeInspector:
        def batch_inspect(self, cases, max_workers=2):
            assert cases == []
            return []

    monkeypatch.setattr(server, "FintechDataGenerator", FakeGenerator)
    monkeypatch.setattr(server, "FraudDetector", FakeDetector)
    monkeypatch.setattr(server, "LLMInspector", FakeInspector)
    stream_response = client.post("/api/pipeline/stream", json={}, headers=headers)
    assert stream_response.status_code == 200
    assert stream_response.headers["content-type"].startswith("text/event-stream")
    assert "event: complete" in stream_response.text
    assert (tmp_path / "records" / "cases" / "D6C2-LOCAL.json").is_file()


def test_oversized_pipeline_stream_body_is_rejected_before_stream_work(api_context, monkeypatch):
    server, client, repo, _ = api_context
    _private_mode(monkeypatch)
    before = _repo_snapshot(repo)
    generator_calls = []
    monkeypatch.setattr(
        server,
        "FintechDataGenerator",
        lambda **kwargs: generator_calls.append(kwargs),
    )

    payload = json.dumps(
        {
            "input_file": "SentinelAI/logs/test_stream.jsonl",
            "padding": "x" * 70_000,
        }
    )
    response = client.post(
        "/api/pipeline/stream",
        content=payload,
        headers={"Content-Type": "application/json", "X-API-Key": TEST_API_KEY},
    )

    assert response.status_code == 413
    assert response.headers.get("content-type", "").startswith("application/json")
    assert "text/event-stream" not in response.headers.get("content-type", "")
    assert generator_calls == []
    assert _repo_snapshot(repo) == before


def test_chunked_oversized_pipeline_stream_is_bounded_before_route_work(api_context, monkeypatch):
    server, _, repo, _ = api_context
    _private_mode(monkeypatch)
    before = _repo_snapshot(repo)
    generator_calls = []
    monkeypatch.setattr(
        server,
        "FintechDataGenerator",
        lambda **kwargs: generator_calls.append(kwargs),
    )

    chunks = [
        b'{"input_file":"SentinelAI/logs/test_stream.jsonl","padding":"' + b"x" * 40_000,
        b"x" * 40_000 + b'"}',
    ]
    incoming = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]
    responses = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/pipeline/stream",
        "raw_path": b"/api/pipeline/stream",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"transfer-encoding", b"chunked"),
            (b"x-api-key", TEST_API_KEY.encode("ascii")),
        ],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
        "root_path": "",
    }

    async def receive():
        return incoming.pop(0) if incoming else {"type": "http.disconnect"}

    async def send(message):
        responses.append(message)

    asyncio.run(server.app(scope, receive, send))

    start = next(message for message in responses if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"")
        for message in responses
        if message["type"] == "http.response.body"
    )
    assert start["status"] == 413
    assert b"Request body too large" in body
    assert generator_calls == []
    assert _repo_snapshot(repo) == before


def test_invalid_private_key_is_rejected_before_body_parsing(api_context, monkeypatch):
    _, client, _, _ = api_context
    _private_mode(monkeypatch)

    malformed_oversized = client.post(
        "/api/pipeline/stream",
        content=b"{" + b"x" * 70_000,
        headers={"Content-Type": "application/json", "X-API-Key": "wrong"},
    )

    assert malformed_oversized.status_code == 401
    assert malformed_oversized.json() == {"detail": "Unauthorized"}


def test_case_and_pipeline_inputs_are_bounded_and_path_safe(api_context, monkeypatch):
    _, client, repo, _ = api_context
    _private_mode(monkeypatch)
    headers = {"X-API-Key": TEST_API_KEY}
    before = _repo_snapshot(repo)

    oversized_body = client.post(
        "/api/cases",
        content=json.dumps({"description": "x" * 70_000}),
        headers={"Content-Type": "application/json", **headers},
    )
    validation_canary = "sensitive-validation-canary"
    too_long_description = client.post(
        "/api/cases",
        json={"description": validation_canary * 200},
        headers=headers,
    )
    arbitrary_path = client.post(
        "/api/pipeline/run",
        json={"input_file": "../../etc/passwd"},
        headers=headers,
    )

    assert oversized_body.status_code == 413
    assert too_long_description.status_code == 422
    assert validation_canary not in too_long_description.text
    assert arbitrary_path.status_code == 422
    assert _repo_snapshot(repo) == before


def test_openapi_marks_all_three_post_routes_as_key_protected(api_context):
    _, client, _, _ = api_context
    schema = client.get("/openapi.json").json()
    protected = ("/api/cases", "/api/pipeline/run", "/api/pipeline/stream")
    for path in protected:
        operation = schema["paths"][path]["post"]
        assert operation.get("security"), f"{path} is missing an OpenAPI security requirement"


def test_public_read_routes_remain_available_and_legacy_routes_unmounted(api_context):
    _, client, _, _ = api_context

    assert client.get("/").status_code == 200
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/cases").status_code == 200
    assert client.get("/api/verdicts").status_code == 200
    assert client.get("/api/tickets").status_code == 200
    assert client.get("/api/emails").status_code == 200
    assert client.get("/api/reports").status_code == 200
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/v1/stats").status_code == 404
    assert client.get("/api/v1/history").status_code == 404
    assert client.get("/api/v1/audit").status_code == 404
    assert client.post("/api/v1/transactions", json={}).status_code == 404
    assert client.post("/api/v1/simulate").status_code == 404
    assert client.get("/ws").status_code == 404


def test_cors_is_same_origin_by_default_and_wildcards_are_discarded(api_context):
    server, client, _, _ = api_context
    assert server.parse_cors_origins("") == []
    assert server.parse_cors_origins("https://demo.example, *, https://admin.example") == [
        "https://demo.example",
        "https://admin.example",
    ]

    cors = next(item for item in server.app.user_middleware if item.cls is CORSMiddleware)
    assert cors.kwargs["allow_credentials"] is False
    assert "*" not in cors.kwargs["allow_origins"]
    assert set(cors.kwargs["allow_methods"]) == {"GET", "POST"}

    preflight = client.options(
        "/api/cases",
        headers={
            "Origin": "https://unapproved.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-api-key",
        },
    )
    assert "access-control-allow-origin" not in preflight.headers


def test_global_exception_response_does_not_echo_internal_message(api_context):
    server, _, _, _ = api_context
    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/internal",
            "raw_path": b"/internal",
            "query_string": b"",
            "headers": [],
            "client": ("testclient", 12345),
            "server": ("testserver", 80),
            "root_path": "",
        }
    )
    secret_canary = "internal-secret-error-canary"
    response = asyncio.run(server.global_exception_handler(request, RuntimeError(secret_canary)))

    assert response.status_code == 500
    assert secret_canary.encode() not in response.body
    assert b"request_id" in response.body


def test_mock_llm_ignores_even_a_present_groq_key(monkeypatch):
    from SentinelAI.ai import groq_client

    monkeypatch.setenv("SENTINELAI_LLM_MODE", "mock")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_value_that_must_never_be_used")

    def forbidden_groq_init(*args, **kwargs):
        raise AssertionError("Groq SDK must not initialize in mock mode")

    monkeypatch.setattr(groq_client, "Groq", forbidden_groq_init)
    client = groq_client.GroqClient()

    assert client.client is None
    assert client._is_mock_key is True
    assert client.complete("system", "user").startswith("Simulated Groq AI completion")
    assert client.get_stats()["mode"] == "SIMULATION"


def test_live_llm_mode_fails_closed_without_real_key(monkeypatch):
    from SentinelAI.ai.groq_client import GroqClient

    monkeypatch.setenv("SENTINELAI_LLM_MODE", "live")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="non-placeholder GROQ_API_KEY"):
        GroqClient()

    monkeypatch.setenv("GROQ_API_KEY", "gsk_your_actual_api_key_here")
    with pytest.raises(RuntimeError, match="non-placeholder GROQ_API_KEY"):
        GroqClient()


def test_explicit_live_mode_initializes_only_a_test_double(monkeypatch):
    from SentinelAI.ai import groq_client

    initialized = []

    class FakeGroq:
        def __init__(self, *, api_key, timeout):
            initialized.append((api_key, timeout))

    monkeypatch.setenv("SENTINELAI_LLM_MODE", "live")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_only_key_for_fake_sdk_123456789")
    monkeypatch.setattr(groq_client, "Groq", FakeGroq)

    client = groq_client.GroqClient()

    assert client.mode == "live"
    assert client.client is not None
    assert initialized == [("gsk_test_only_key_for_fake_sdk_123456789", client.timeout)]


def test_api_key_is_never_written_to_logs(api_context, monkeypatch, caplog):
    _, client, _, _ = api_context
    _private_mode(monkeypatch)
    caplog.clear()
    client.post(
        "/api/cases",
        json={"risk_score": 1.0},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert TEST_API_KEY not in caplog.text
