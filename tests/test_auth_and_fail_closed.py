"""Tests for Bearer token authentication middleware and fail-closed guardrail behavior."""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config import settings
from app.guardrail_service import GuardrailService
from app.llm import OllamaLLM, LLMBackendError
from app.security import SafetyAction


@pytest.mark.asyncio
async def test_token_generated_with_sufficient_entropy():
    """Default API_AUTH_TOKEN is generated via secrets.token_urlsafe(48) (>= 64 chars)."""
    assert settings.API_AUTH_TOKEN
    assert len(settings.API_AUTH_TOKEN) >= 64


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/chat", "/chat/protected", "/chat/baseline"])
async def test_chat_endpoints_reject_missing_bearer_token(endpoint: str):
    """Requests without Authorization header fail closed with 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(endpoint, json={"message": "Hello"})
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["/chat", "/chat/protected", "/security/metrics", "/security/audit"])
async def test_protected_endpoints_reject_invalid_bearer_token(endpoint: str):
    """Requests with an invalid Bearer token fail closed with 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": "Bearer invalid-token-value"},
    ) as client:
        method = client.get if endpoint.startswith("/security/") else client.post
        kwargs = {} if endpoint.startswith("/security/") else {"json": {"message": "Hello"}}
        resp = await method(endpoint, **kwargs)
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_public_health_endpoint_does_not_require_token():
    """GET /health remains accessible without auth for liveness probes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_fail_closed_when_nemo_unavailable(monkeypatch):
    """When REQUIRE_NEMO_RAILS=True and nemo_rails is None, pipeline fails closed."""
    monkeypatch.setattr(settings, "REQUIRE_NEMO_RAILS", True)
    service = GuardrailService()
    service.nemo_rails = None

    resp = await service.process_protected("What is the capital of France?")
    assert resp.status == SafetyAction.INPUT_BLOCKED
    assert "FAIL_CLOSED_NEMO_UNAVAILABLE" in resp.rules_triggered


@pytest.mark.asyncio
async def test_fail_closed_when_nemo_runtime_errors(monkeypatch):
    """When ENABLE_NEMO_RUNTIME=True and NeMo raises, pipeline fails closed."""
    monkeypatch.setattr(settings, "ENABLE_NEMO_RUNTIME", True)

    class BrokenNemo:
        async def generate_async(self, messages):
            raise RuntimeError("Simulated NeMo internal error")

    service = GuardrailService()
    service.nemo_rails = BrokenNemo()

    resp = await service.process_protected("What is the capital of France?")
    assert resp.status == SafetyAction.INPUT_BLOCKED
    assert "FAIL_CLOSED_NEMO_ERROR" in resp.rules_triggered


@pytest.mark.asyncio
async def test_fail_closed_when_ollama_unreachable(monkeypatch):
    """When Ollama is unreachable under FAIL_CLOSED=True, raise LLMBackendError -> 503."""
    monkeypatch.setattr(settings, "FAIL_CLOSED", True)
    # Point to an unused local port so connection is refused immediately
    unreachable_ollama = OllamaLLM(base_url="http://127.0.0.1:59999", model="llama3")
    with pytest.raises(LLMBackendError):
        await unreachable_ollama.generate("Hello")


def test_canary_token_is_dynamic_and_env_driven(monkeypatch):
    """SYSTEM_CANARY_TOKEN is dynamically generated per deployment and respects env overrides."""
    from app.config import Settings

    monkeypatch.delenv("SYSTEM_CANARY_TOKEN", raising=False)
    s1 = Settings(_env_file=None)
    s2 = Settings(_env_file=None)
    assert s1.SYSTEM_CANARY_TOKEN.startswith("CANARY_")
    assert len(s1.SYSTEM_CANARY_TOKEN) >= 32
    assert s1.SYSTEM_CANARY_TOKEN != s2.SYSTEM_CANARY_TOKEN
    assert "SECURE_CANARY_77A8B9C0" not in s1.SYSTEM_CANARY_TOKEN

    monkeypatch.setenv("SYSTEM_CANARY_TOKEN", "ENV_ROTATED_CANARY_XYZ")
    s3 = Settings(_env_file=None)
    assert s3.SYSTEM_CANARY_TOKEN == "ENV_ROTATED_CANARY_XYZ"
