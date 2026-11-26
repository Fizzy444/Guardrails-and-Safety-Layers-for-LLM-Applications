"""FastAPI application entry point providing Baseline, Protected, and Security Telemetry endpoints."""

import hmac
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import settings
from app.guardrail_service import guardrail_service, ChatRequest, ChatResponse
from app.llm import LLMBackendError
from app.security import audit_logger

PUBLIC_PATHS = {"/", "/health", "/api/info", "/docs", "/redoc", "/openapi.json"}

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("securellm_app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        f"Starting {settings.APP_NAME} in '{settings.APP_ENV}' mode "
        f"(LLM Provider: {settings.LLM_PROVIDER}, Bearer Auth: enabled, "
        f"Token prefix: {settings.API_AUTH_TOKEN[:8]}...)."
    )
    yield
    logger.info(f"Shutting down {settings.APP_NAME}.")


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Multi-Layered LLM Guardrails & Safety Architecture",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def bearer_auth_middleware(request: Request, call_next):
    """Enforce Bearer token authentication on all protected API endpoints (fail-closed)."""
    if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, settings.API_AUTH_TOKEN):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing or invalid Bearer token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await call_next(request)


@app.get("/api/info", tags=["General"])
async def api_info():
    """System overview and operational status."""
    return {
        "project": settings.APP_NAME,
        "status": "operational",
        "version": "1.0.0",
        "port": settings.PORT,
        "llm_provider": settings.LLM_PROVIDER,
        "guardrails_active": {
            "input_validation": settings.ENABLE_INPUT_VALIDATION,
            "output_validation": settings.ENABLE_OUTPUT_VALIDATION,
            "canary_protection": settings.ENABLE_CANARY_CHECK,
            "pii_scrubbing": settings.ENABLE_PII_SCRUBBING,
            "audit_logging": settings.ENABLE_AUDIT_LOGGING,
        },
        "endpoints": {
            "web_ui": "GET /",
            "baseline_chat": "POST /chat/baseline",
            "protected_chat": "POST /chat/protected",
            "unified_chat": "POST /chat",
            "security_metrics": "GET /security/metrics",
            "security_audit": "GET /security/audit",
            "red_team_run": "POST /security/redteam/run",
            "red_team_report": "GET /security/redteam/report",
            "swagger_docs": "GET /docs"
        }
    }


@app.get("/", response_class=HTMLResponse, tags=["General"])
async def root():
    """Minimal, clean test UI for SecureLLM."""
    if TEMPLATE_PATH.exists():
        return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SecureLLM API Operational</h1>")


@app.get("/health", tags=["General"])
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "llm_provider": settings.LLM_PROVIDER,
        "nemo_rails_loaded": guardrail_service.nemo_rails is not None
    }


@app.post("/chat/baseline", response_model=ChatResponse, tags=["Chat"])
async def chat_baseline(request: ChatRequest, req: Request):
    """
    Day 2 Deliverable: Unprotected Baseline Chatbot.
    Direct LLM completion with NO guardrails or safety filters.
    Used to demonstrate vulnerabilities against red-team attacks.
    """
    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        response = await guardrail_service.process_baseline(request.message, client_ip=client_ip)
        return response
    except LLMBackendError as e:
        logger.error(f"LLM backend unavailable in baseline chat: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Error in baseline chat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat/protected", response_model=ChatResponse, tags=["Chat"])
async def chat_protected(request: ChatRequest, req: Request):
    """
    Day 3 & 4 Deliverable: Multi-Layer Protected Chatbot.
    Runs Input Validation -> NeMo Guardrails -> LLM -> Output Safety & PII Redaction -> Audit Log.
    """
    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        response = await guardrail_service.process_protected(request.message, client_ip=client_ip)
        return response
    except LLMBackendError as e:
        logger.error(f"LLM backend unavailable in protected chat: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Error in protected chat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat", response_model=ChatResponse, tags=["Chat"])
async def chat_unified(request: ChatRequest, req: Request):
    """
    Unified chat endpoint. Routes to Protected (default) or Baseline based on `use_guardrails` flag.
    """
    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        if request.use_guardrails:
            return await guardrail_service.process_protected(request.message, client_ip=client_ip)
        else:
            return await guardrail_service.process_baseline(request.message, client_ip=client_ip)
    except LLMBackendError as e:
        logger.error(f"LLM backend unavailable in unified chat: {e}")
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/security/audit", tags=["Security Telemetry"])
async def get_audit_logs(limit: int = Query(default=20, ge=1, le=200)):
    """Retrieve recent structured security events and blocked requests."""
    logs = audit_logger.get_recent_logs(limit=limit)
    return {
        "count": len(logs),
        "events": logs
    }


@app.get("/security/metrics", tags=["Security Telemetry"])
async def get_security_metrics():
    """Retrieve aggregated security statistics and blocking metrics."""
    return audit_logger.get_metrics()


@app.post("/security/redteam/run", tags=["Red-Team Testing"])
async def trigger_red_team_suite():
    """
    Day 5 Deliverable: Execute the 10-scenario Red-Team Attack Benchmark.
    Tests each attack against both Baseline and Protected pipelines.
    Returns comparison table, blocking rate, and detailed findings.
    """
    from tests.red_team_tests import run_full_red_team_suite, generate_markdown_report
    try:
        suite_data = await run_full_red_team_suite()
        # Save updated markdown report
        report_text = generate_markdown_report(suite_data)
        report_path = settings.base_dir / "reports" / "red_team_report.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_text, encoding="utf-8")
        return suite_data
    except Exception as e:
        logger.error(f"Red-team execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/security/redteam/report", tags=["Red-Team Testing"])
async def get_red_team_report():
    """Retrieve the generated Day 5 Red-Team Markdown report."""
    report_path = settings.base_dir / "reports" / "red_team_report.md"
    if not report_path.exists():
        from tests.red_team_tests import run_full_red_team_suite, generate_markdown_report
        suite_data = await run_full_red_team_suite()
        report_text = generate_markdown_report(suite_data)
        report_path.write_text(report_text, encoding="utf-8")
    return {"report_markdown": report_path.read_text(encoding="utf-8")}
