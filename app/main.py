"""FastAPI application entry point providing Baseline, Protected, and Security Telemetry endpoints."""

import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.config import settings
from app.guardrail_service import guardrail_service, ChatRequest, ChatResponse
from app.security import audit_logger

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("securellm_app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} in '{settings.APP_ENV}' mode (LLM Provider: {settings.LLM_PROVIDER}).")
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
    except Exception as e:
        logger.error(f"Error in protected chat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat", response_model=ChatResponse, tags=["Chat"])
async def chat_unified(request: ChatRequest, req: Request):
    """
    Unified chat endpoint. Routes to Protected (default) or Baseline based on `use_guardrails` flag.
    """
    client_ip = req.client.host if req.client else "127.0.0.1"
    if request.use_guardrails:
        return await guardrail_service.process_protected(request.message, client_ip=client_ip)
    else:
        return await guardrail_service.process_baseline(request.message, client_ip=client_ip)


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
