"""Contract tests for proxy_starter.py. Run: pytest migration/test_proxy.py"""
import os
import re
from pathlib import Path

os.environ.setdefault("ANTHROPIC_API_KEY", "sk-test-not-real")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import proxy_starter as ps  # noqa: E402

client = TestClient(ps.app)
GOOD = {"system": "s", "user": "u"}


class FakeUpstream:
    """Stands in for httpx.AsyncClient so no test touches the network."""
    calls: list = []
    status = 200

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def post(self, url, json=None, headers=None):
        FakeUpstream.calls.append({"url": url, "json": json, "headers": headers})
        body = {"content": [{"type": "text", "text": "{}"}], "usage": {"input_tokens": 1, "output_tokens": 1}}
        return httpx.Response(FakeUpstream.status, json=body)


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeUpstream.calls, FakeUpstream.status = [], 200
    ps._buckets.clear()
    monkeypatch.setattr(ps.httpx, "AsyncClient", FakeUpstream)


def sent():
    return FakeUpstream.calls[-1]["json"]


def test_forwards_fixed_model_and_system():
    r = client.post("/api/claude", json=GOOD)
    assert r.status_code == 200 and "content" in r.json()
    assert sent()["model"] == ps.MODEL and sent()["system"] == "s"
    assert sent()["messages"] == [{"role": "user", "content": "u"}]
    assert "tools" not in sent()
    assert FakeUpstream.calls[-1]["headers"]["x-api-key"] == "sk-test-not-real"


def test_frontend_cannot_choose_model_or_tools():
    client.post("/api/claude", json={**GOOD, "model": "evil", "tools": [{"type": "bash"}], "messages": []})
    assert sent()["model"] == ps.MODEL and "tools" not in sent()


@pytest.mark.parametrize("scope,uses", [("web", 4), ("docs", 3), ("cisa", 3)])
def test_search_scopes_map_to_fixed_tool_config(scope, uses):
    client.post("/api/claude", json={**GOOD, "enableWebSearch": True, "searchScope": scope})
    tool = sent()["tools"][0]
    assert tool["name"] == "web_search" and tool["max_uses"] == uses
    assert ("allowed_domains" in tool) == (scope != "web")


def test_search_defaults_to_open_web_and_rejects_unknown_scope():
    client.post("/api/claude", json={**GOOD, "enableWebSearch": True})
    assert "allowed_domains" not in sent()["tools"][0]
    r = client.post("/api/claude", json={**GOOD, "enableWebSearch": True, "searchScope": "../../etc"})
    assert r.status_code == 400 and "error" in r.json()


def test_max_tokens_is_clamped_not_rejected():
    assert client.post("/api/claude", json={**GOOD, "maxTokens": 999999}).status_code == 200
    assert sent()["max_tokens"] == ps.MAX_TOKENS_CAP


@pytest.mark.parametrize("bad", [{"system": ""}, {"user": "x" * 8001}, {"system": "x" * 12001}, {"maxTokens": 0}])
def test_validation_returns_400_with_error_shape(bad):
    r = client.post("/api/claude", json={**GOOD, **bad})
    assert r.status_code == 400 and "message" in r.json()["error"]


def test_upstream_failure_is_502_with_error_shape():
    FakeUpstream.status = 500
    r = client.post("/api/claude", json=GOOD)
    assert r.status_code == 502 and "message" in r.json()["error"]


def test_rate_limit_returns_429_with_retry_after():
    for _ in range(20):
        assert client.post("/api/claude", json=GOOD).status_code == 200
    r = client.post("/api/claude", json=GOOD)
    assert r.status_code == 429 and r.headers["retry-after"] == "60"


def test_health_and_version():
    assert client.get("/health").json()["ok"] is True
    assert client.get("/version").json()["spec"] == "otter-shell/proxy/v1.1"


def test_docs_domains_match_frontend():
    src = (Path(__file__).parent.parent / "src" / "OtterShell.jsx").read_text()
    m = re.search(r"const DOC_DOMAINS = \[(.*?)\];", src)
    assert m and re.findall(r'"([^"]+)"', m.group(1)) == ps.DOC_DOMAINS
