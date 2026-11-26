"""Guardrail Service coordinating Layer 1 (Heuristics), Layer 2 (NeMo Rails), Layer 3 (LLM), and Layer 4 (Output Safety & PII)."""

import time
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.config import settings
from app.llm import get_llm, BaseLLM, LLMBackendError
from app.security import (
    validate_input,
    validate_and_sanitize_output,
    audit_logger,
    SafetyAction,
    ValidationResult
)

logger = logging.getLogger("guardrail_service")


class ChatRequest(BaseModel):
    message: str = Field(..., description="User message or prompt", min_length=1)
    use_guardrails: bool = Field(default=True, description="Whether to apply security guardrails")


class ChatResponse(BaseModel):
    response: str
    status: SafetyAction
    guardrails_applied: bool
    rules_triggered: List[str]
    latency_ms: float
    timestamp: str


class GuardrailService:
    """
    Coordinates multi-layered security pipelines:
    - Layer 1: Deterministic input validation & regex heuristics
    - Layer 2: NeMo Guardrails Colang flows & intent classification
    - Layer 3: Controlled LLM execution with canary isolation
    - Layer 4: Output verification, canary check, and PII redaction
    - Layer 5: Structured audit logging
    """

    def __init__(self, llm: Optional[BaseLLM] = None):
        self.llm = llm or get_llm()
        self.canary_token = settings.SYSTEM_CANARY_TOKEN
        self.system_prompt = (
            f"{settings.SYSTEM_PROMPT.replace('[CANARY_TOKEN]', self.canary_token)}\n"
            f"CANARY_SECRET_MARKER: {self.canary_token}"
        )
        self.nemo_rails = None
        self._init_nemo()

    def _init_nemo(self):
        """Initialize NeMo Guardrails if configuration is present."""
        try:
            import os
            from nemoguardrails import RailsConfig, LLMRails
            if not os.environ.get("OPENAI_API_KEY"):
                os.environ["OPENAI_API_KEY"] = "mock-key-for-guardrails"

            config_path = settings.base_dir / "guardrails"
            if config_path.exists():
                config = RailsConfig.from_path(str(config_path))
                self.nemo_rails = LLMRails(config)
                logger.info("NeMo Guardrails engine successfully initialized from guardrails/ directory.")
        except Exception as e:
            logger.warning(f"NeMo Guardrails initialization deferred or running in hybrid mode: {e}")

    async def process_baseline(self, message: str, client_ip: str = "127.0.0.1") -> ChatResponse:
        """
        Unprotected Baseline Chatbot execution.
        Bypasses all safety layers and returns raw LLM response.
        Used for vulnerability demonstration and red-team baseline comparison.
        """
        start_time = time.perf_counter()

        # Call LLM directly with standard prompt and canary
        raw_response = await self.llm.generate(prompt=message, system_prompt=self.system_prompt)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Log audit entry as baseline unprotected
        audit_logger.log_event(
            event_type="BASELINE_QUERY",
            user_input=message,
            response_text=raw_response,
            action=SafetyAction.ALLOWED,
            rules_triggered=["BASELINE_UNPROTECTED"],
            client_ip=client_ip,
            latency_ms=latency_ms,
            metadata={"mode": "baseline_unprotected"}
        )

        return ChatResponse(
            response=raw_response,
            status=SafetyAction.ALLOWED,
            guardrails_applied=False,
            rules_triggered=["BASELINE_UNPROTECTED"],
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    def _fail_closed_response(
        self,
        start_time: float,
        message: str,
        client_ip: str,
        reason: str,
        rule_id: str,
        action: SafetyAction = SafetyAction.INPUT_BLOCKED,
    ) -> ChatResponse:
        """Return a deterministic fail-closed refusal and record an audit event."""
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        refusal_response = f"Security Refusal (Fail-Closed): {reason}"
        audit_logger.log_event(
            event_type="FAIL_CLOSED_BLOCKED",
            user_input=message,
            response_text=refusal_response,
            action=action,
            rules_triggered=[rule_id],
            client_ip=client_ip,
            latency_ms=latency_ms,
            metadata={"fail_closed": True, "reason": reason}
        )
        return ChatResponse(
            response=refusal_response,
            status=action,
            guardrails_applied=True,
            rules_triggered=[rule_id],
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    async def process_protected(self, message: str, client_ip: str = "127.0.0.1") -> ChatResponse:
        """
        Multi-Layer Protected Pipeline (Fail-Closed):
        Input Validation -> NeMo Rails -> LLM -> Output Verification -> Audit Log
        """
        start_time = time.perf_counter()

        # --- LAYER 1: Deterministic Input Validation & Heuristics ---
        try:
            val_result: ValidationResult = validate_input(message)
        except Exception as e:
            logger.error(f"Input validator error (fail-closed): {e}")
            return self._fail_closed_response(
                start_time, message, client_ip,
                reason="Input validation engine encountered an internal error.",
                rule_id="FAIL_CLOSED_INPUT_VALIDATOR_ERROR",
                action=SafetyAction.INPUT_BLOCKED,
            )

        if not val_result.valid:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            refusal_response = (
                f"Security Refusal: {val_result.reason} "
                f"[Category: {val_result.category}]"
            )

            audit_logger.log_event(
                event_type="INPUT_GUARDRAIL_BLOCKED",
                user_input=message,
                response_text=refusal_response,
                action=SafetyAction.INPUT_BLOCKED,
                rules_triggered=val_result.rules_triggered,
                client_ip=client_ip,
                latency_ms=latency_ms,
                metadata={"category": val_result.category, "details": val_result.details}
            )

            return ChatResponse(
                response=refusal_response,
                status=SafetyAction.INPUT_BLOCKED,
                guardrails_applied=True,
                rules_triggered=val_result.rules_triggered,
                latency_ms=round(latency_ms, 2),
                timestamp=datetime.now(timezone.utc).isoformat()
            )

        # --- LAYER 2: NeMo Guardrails Colang Flow Check ---
        triggered_rules: List[str] = list(val_result.rules_triggered)
        if settings.REQUIRE_NEMO_RAILS and self.nemo_rails is None:
            logger.error("NeMo Guardrails unavailable while REQUIRE_NEMO_RAILS=True (fail-closed).")
            return self._fail_closed_response(
                start_time, message, client_ip,
                reason="NeMo Guardrails engine is unavailable.",
                rule_id="FAIL_CLOSED_NEMO_UNAVAILABLE",
                action=SafetyAction.INPUT_BLOCKED,
            )

        if settings.ENABLE_NEMO_RUNTIME and self.nemo_rails is not None:
            try:
                nemo_resp = await self.nemo_rails.generate_async(
                    messages=[{"role": "user", "content": message}]
                )
                nemo_content = (
                    nemo_resp.get("content", "")
                    if isinstance(nemo_resp, dict)
                    else str(nemo_resp)
                )
                if "Security Alert:" in nemo_content:
                    latency_ms = (time.perf_counter() - start_time) * 1000.0
                    triggered_rules.append("NEMO_COLANG_BLOCKED")
                    audit_logger.log_event(
                        event_type="INPUT_GUARDRAIL_BLOCKED",
                        user_input=message,
                        response_text=nemo_content,
                        action=SafetyAction.INPUT_BLOCKED,
                        rules_triggered=triggered_rules,
                        client_ip=client_ip,
                        latency_ms=latency_ms,
                        metadata={"source": "nemo_rails"}
                    )
                    return ChatResponse(
                        response=nemo_content,
                        status=SafetyAction.INPUT_BLOCKED,
                        guardrails_applied=True,
                        rules_triggered=triggered_rules,
                        latency_ms=round(latency_ms, 2),
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
            except Exception as e:
                logger.error(f"NeMo Guardrails runtime error (fail-closed): {e}")
                return self._fail_closed_response(
                    start_time, message, client_ip,
                    reason="NeMo Guardrails runtime check failed.",
                    rule_id="FAIL_CLOSED_NEMO_ERROR",
                    action=SafetyAction.INPUT_BLOCKED,
                )

        # --- LAYER 3: Controlled LLM Execution ---
        try:
            raw_response = await self.llm.generate(prompt=message, system_prompt=self.system_prompt)
        except LLMBackendError as e:
            logger.error(f"LLM backend unavailable (fail-closed): {e}")
            audit_logger.log_event(
                event_type="FAIL_CLOSED_LLM_UNAVAILABLE",
                user_input=message,
                response_text=str(e),
                action=SafetyAction.OUTPUT_BLOCKED,
                rules_triggered=["FAIL_CLOSED_LLM_UNREACHABLE"],
                client_ip=client_ip,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                metadata={"fail_closed": True}
            )
            raise

        # --- LAYER 4: Output Safety, Canary Verification & PII Redaction ---
        try:
            sanitized_response, output_action, output_rules = validate_and_sanitize_output(
                output_text=raw_response,
                canary_token=self.canary_token,
                system_prompt=self.system_prompt
            )
        except Exception as e:
            logger.error(f"Output validator error (fail-closed): {e}")
            return self._fail_closed_response(
                start_time, message, client_ip,
                reason="Output verification engine encountered an internal error.",
                rule_id="FAIL_CLOSED_OUTPUT_VALIDATOR_ERROR",
                action=SafetyAction.OUTPUT_BLOCKED,
            )

        triggered_rules.extend(output_rules)
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # --- LAYER 5: Structured Telemetry & Audit Logging ---
        event_type = "OUTPUT_GUARDRAIL_BLOCKED" if output_action == SafetyAction.OUTPUT_BLOCKED else (
            "OUTPUT_REDACTED" if output_action == SafetyAction.OUTPUT_REDACTED else "SAFE_QUERY"
        )

        audit_logger.log_event(
            event_type=event_type,
            user_input=message,
            response_text=sanitized_response,
            action=output_action,
            rules_triggered=triggered_rules,
            client_ip=client_ip,
            latency_ms=latency_ms,
            metadata={"raw_output_length": len(raw_response)}
        )

        return ChatResponse(
            response=sanitized_response,
            status=output_action,
            guardrails_applied=True,
            rules_triggered=triggered_rules,
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat()
        )


guardrail_service = GuardrailService()
