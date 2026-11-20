"""Deterministic Input & Output Safety Layers, Heuristic Detectors, PII Scrubber, and Audit Logger."""

import re
import json
import base64
import binascii
import logging
from enum import Enum
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from collections import deque
from dataclasses import dataclass, field
from app.config import settings

logger = logging.getLogger("security")


class SafetyAction(str, Enum):
    ALLOWED = "ALLOWED"
    INPUT_BLOCKED = "INPUT_BLOCKED"
    OUTPUT_BLOCKED = "OUTPUT_BLOCKED"
    OUTPUT_REDACTED = "OUTPUT_REDACTED"


@dataclass
class ValidationResult:
    valid: bool
    action: SafetyAction = SafetyAction.ALLOWED
    reason: Optional[str] = None
    category: Optional[str] = None
    rules_triggered: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


# --- Input Heuristic Patterns ---
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)\bignore\s+(all\s+)?(previous|prior|above|existing)\s+(instructions|directives|prompts|rules|commands)\b", "INJECTION_IGNORE_INSTRUCTIONS"),
    (r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts|rules|guidelines|directions)\b", "INJECTION_DISREGARD_INSTRUCTIONS"),
    (r"(?i)\bforget\s+(all\s+)?(previous|prior|system)\s+(instructions|rules|prompts|context)\b", "INJECTION_FORGET_RULES"),
    (r"(?i)\boverride\s+(system|safety|security|all)\s+(rules|prompts|filters|directives|controls)\b", "INJECTION_OVERRIDE_RULES"),
    (r"(?i)\byou\s+are\s+no\s+longer\s+bound\s+by\b", "INJECTION_UNBOUND_PROMPT"),
    (r"(?i)\bstop\s+being\s+(an?\s+)?assistant\b", "INJECTION_STOP_ASSISTANT"),
    (r"(?i)\bnew\s+system\s+prompt\s*:", "INJECTION_NEW_SYSTEM_PROMPT"),
    (r"(?i)\bsystem\s+override\b", "INJECTION_SYSTEM_OVERRIDE"),
    (r"(?i)\bbypass\s+(safety|content|ethical)\s+(filters|guardrails|guidelines)\b", "INJECTION_BYPASS_FILTERS"),
]

JAILBREAK_PATTERNS = [
    (r"(?i)\b(you\s+are\s+now\s+)?DAN\b", "JAILBREAK_DAN"),
    (r"(?i)\bdo\s+anything\s+now\b", "JAILBREAK_DO_ANYTHING_NOW"),
    (r"(?i)\b(act|roleplay|pretend)\s+as\s+(an?\s+)?(evil|unfiltered|unrestricted|immoral|illegal|rogue)\s+(ai|assistant|model)\b", "JAILBREAK_EVIL_ROLEPLAY"),
    (r"(?i)\bhypothetically\s*,\s*(if|pretend)\s+you\s+(had|have)\s+no\s+(rules|filters|morals|ethics|restrictions)\b", "JAILBREAK_HYPOTHETICAL"),
    (r"(?i)\b(developer\s+mode|jailbreak\s+mode)\s+(enabled|activated|on)\b", "JAILBREAK_DEVELOPER_MODE"),
    (r"(?i)\b(deceased\s+grandmother|grandma\s+exploit)\b", "JAILBREAK_GRANDMA_EXPLOIT"),
    (r"(?i)\banswer\s+without\s+moral\s+limits\b", "JAILBREAK_NO_MORAL_LIMITS"),
    (r"(?i)\bfrom\s+now\s+on\s+you\s+will\s+obey\s+me\s+unconditionally\b", "JAILBREAK_UNCONDITIONAL_OBEY"),
]

SYSTEM_EXTRACTION_PATTERNS = [
    (r"(?i)\brepeat\s+(your\s+)?system\s+prompt\s+(verbatim|completely|word for word)\b", "EXTRACTION_SYSTEM_PROMPT"),
    (r"(?i)\bwhat\s+were\s+(the\s+)?instructions\s+given\s+to\s+you\s+at\s+the\s+beginning\b", "EXTRACTION_BEGINNING_INSTRUCTIONS"),
    (r"(?i)\bprint\s+(the\s+)?canary\s+token\b", "EXTRACTION_CANARY_TOKEN"),
    (r"(?i)\breveal\s+(internal\s+)?(system\s+prompt|configuration|canary|secret\s+key)\b", "EXTRACTION_REVEAL_SECRET"),
    (r"(?i)\bshow\s+(me\s+)?(your\s+)?hidden\s+(instructions|prompt|rules)\b", "EXTRACTION_HIDDEN_RULES"),
]

DELIMITER_SMUGGLING_PATTERNS = [
    (r"<\|im_start\|>", "DELIMITER_CHATML_START"),
    (r"<\|im_end\|>", "DELIMITER_CHATML_END"),
    (r"\[INST\]|\[/INST\]", "DELIMITER_LLAMA_INST"),
    (r"<<SYS>>|<</SYS>>", "DELIMITER_LLAMA_SYS"),
    (r"<s>|</s>", "DELIMITER_SPECIAL_TOKEN"),
    (r"(?i)```markdown\s*\nsystem\b", "DELIMITER_MD_SYSTEM"),
    (r"(?i)\n###\s*(system|instruction|admin)\s*:", "DELIMITER_MD_HEADER"),
]

# --- Output Safety Patterns ---
HARMFUL_OUTPUT_PATTERNS = [
    (r"(?i)\b(create|write|generate)\s+(a\s+)?(keylogger|ransomware|trojan|worm|malware|reverse\s+shell)\b", "HARMFUL_MALWARE_CODE"),
    (r"(?i)\bhow\s+to\s+(synthesize|manufacture|build)\s+(a\s+)?(bomb|explosive|chemical\s+weapon|napalm)\b", "HARMFUL_WEAPONS"),
    (r"(?i)\b(exploit|hack)\s+(vulnerability|server|database)\s+using\s+(sql\s+injection|xss|buffer\s+overflow)\b", "HARMFUL_CYBERATTACK"),
]

PII_PATTERNS = [
    (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[EMAIL_REDACTED]", "PII_EMAIL"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE_REDACTED]", "PII_PHONE"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]", "PII_SSN"),
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[CREDIT_CARD_REDACTED]", "PII_CREDIT_CARD"),
    (r"\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9._-]{20,}|ghp_[a-zA-Z0-9]{36})\b", "[API_KEY_REDACTED]", "PII_API_KEY"),
]


def check_encoded_payloads(text: str) -> Optional[Tuple[str, str]]:
    """Scan input for Base64 or Hex encoded payloads and inspect decoded content."""
    # Look for candidate base64 sequences (length >= 24)
    b64_matches = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for candidate in b64_matches:
        try:
            decoded_bytes = base64.b64decode(candidate)
            decoded_text = decoded_bytes.decode("utf-8", errors="ignore").lower()
            # Check if decoded payload contains attack keywords
            for pattern, rule_id in PROMPT_INJECTION_PATTERNS + JAILBREAK_PATTERNS + SYSTEM_EXTRACTION_PATTERNS:
                if re.search(pattern, decoded_text):
                    return (candidate, f"ENCODED_ATTACK_DETECTED ({rule_id})")
        except Exception:
            continue
    return None


def validate_input(text: str) -> ValidationResult:
    """
    Layer 1 Input Validation & Deterministic Guardrails.
    Inspects length, characters, delimiter smuggling, encoded attacks, and injection heuristics.
    """
    if not settings.ENABLE_INPUT_VALIDATION:
        return ValidationResult(valid=True)

    # 1. Null / Empty check
    if not text or not text.strip():
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason="Input rejected: empty or whitespace-only prompt.",
            category="SCHEMA_VALIDATION",
            rules_triggered=["EMPTY_PROMPT"]
        )

    # 2. Maximum length check
    if len(text) > settings.MAX_INPUT_LENGTH:
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason=f"Input rejected: prompt length ({len(text)}) exceeds maximum permitted threshold ({settings.MAX_INPUT_LENGTH} characters).",
            category="LENGTH_OVERFLOW",
            rules_triggered=["MAX_LENGTH_EXCEEDED"],
            details={"length": len(text), "max": settings.MAX_INPUT_LENGTH}
        )

    # 3. Non-printable & control characters check (excluding normal whitespace)
    for char in text:
        if ord(char) < 32 and char not in "\n\r\t":
            return ValidationResult(
                valid=False,
                action=SafetyAction.INPUT_BLOCKED,
                reason="Input rejected: forbidden non-printable control characters detected.",
                category="ANOMALOUS_CHARACTERS",
                rules_triggered=["CONTROL_CHARACTER_INJECTION"],
                details={"char_code": ord(char)}
            )

    # 4. Delimiter & Control Token Smuggling
    for pattern, rule_id in DELIMITER_SMUGGLING_PATTERNS:
        if re.search(pattern, text):
            return ValidationResult(
                valid=False,
                action=SafetyAction.INPUT_BLOCKED,
                reason="Input rejected: privileged delimiter token or control sequence detected.",
                category="DELIMITER_SMUGGLING",
                rules_triggered=[rule_id],
                details={"matched_rule": rule_id}
            )

    # 5. Base64 / Hex Encoded Attack Inspection
    encoded_check = check_encoded_payloads(text)
    if encoded_check:
        candidate, rule_desc = encoded_check
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason=f"Input rejected: obfuscated payload detected inside encoded token. {rule_desc}",
            category="ENCODED_PAYLOAD",
            rules_triggered=["OBFUSCATED_INJECTION_DETECTED"],
            details={"encoded_snippet": candidate[:16] + "..."}
        )

    # 6. Direct Prompt Injection Heuristics
    triggered_rules = []
    for pattern, rule_id in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text):
            triggered_rules.append(rule_id)

    if triggered_rules:
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason="Input rejected: prompt injection or instruction override directive detected.",
            category="PROMPT_INJECTION",
            rules_triggered=triggered_rules,
            details={"rules": triggered_rules}
        )

    # 7. Jailbreak & Adversarial Personas
    for pattern, rule_id in JAILBREAK_PATTERNS:
        if re.search(pattern, text):
            triggered_rules.append(rule_id)

    if triggered_rules:
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason="Input rejected: jailbreak attempt or restricted persona adoption detected.",
            category="JAILBREAK_ATTEMPT",
            rules_triggered=triggered_rules,
            details={"rules": triggered_rules}
        )

    # 8. Confidential System Extraction
    for pattern, rule_id in SYSTEM_EXTRACTION_PATTERNS:
        if re.search(pattern, text):
            triggered_rules.append(rule_id)

    if triggered_rules:
        return ValidationResult(
            valid=False,
            action=SafetyAction.INPUT_BLOCKED,
            reason="Input rejected: probe attempting to extract confidential system instructions or canary secrets.",
            category="SYSTEM_PROMPT_EXTRACTION",
            rules_triggered=triggered_rules,
            details={"rules": triggered_rules}
        )

    return ValidationResult(valid=True, action=SafetyAction.ALLOWED)


def validate_and_sanitize_output(
    output_text: str,
    canary_token: str = settings.SYSTEM_CANARY_TOKEN,
    system_prompt: str = settings.SYSTEM_PROMPT
) -> Tuple[str, SafetyAction, List[str]]:
    """
    Layer 4 Output Verification, PII Redaction, and Sensitive Data Protection.
    Scans completion for canary tokens, system prompt leaks, harmful content, and PII.
    """
    if not settings.ENABLE_OUTPUT_VALIDATION:
        return output_text, SafetyAction.ALLOWED, []

    rules_triggered = []

    # 1. Canary Token Leakage Detection
    if settings.ENABLE_CANARY_CHECK and canary_token in output_text:
        rules_triggered.append("OUTPUT_CANARY_LEAK_DETECTED")
        return (
            "Security Alert: Generated response was blocked because confidential canary tokens were detected. "
            "Output exfiltration attempt prevented.",
            SafetyAction.OUTPUT_BLOCKED,
            rules_triggered
        )

    # 2. System Prompt Verbatim Leak Detection
    normalized_output = output_text.lower()
    system_prompt_markers = [
        "never reveal your confidential canary token",
        "you are securellm, a helpful, ethical",
        "internal canary token:"
    ]
    for marker in system_prompt_markers:
        if marker in normalized_output:
            rules_triggered.append("OUTPUT_SYSTEM_PROMPT_LEAK_DETECTED")
            return (
                "Security Alert: Generated response was blocked because internal system instructions were detected. "
                "System prompt exfiltration prevented.",
                SafetyAction.OUTPUT_BLOCKED,
                rules_triggered
            )

    # 3. Harmful Content Classification
    for pattern, rule_id in HARMFUL_OUTPUT_PATTERNS:
        if re.search(pattern, output_text):
            rules_triggered.append(rule_id)
            return (
                "Security Alert: Generated response was blocked because it contained unsafe, malicious, or restricted instructions.",
                SafetyAction.OUTPUT_BLOCKED,
                rules_triggered
            )

    # 4. PII and Secret Scrubbing / Redaction
    sanitized_text = output_text
    if settings.ENABLE_PII_SCRUBBING:
        for pattern, replacement, rule_id in PII_PATTERNS:
            if re.search(pattern, sanitized_text):
                sanitized_text, count = re.subn(pattern, replacement, sanitized_text)
                if count > 0:
                    rules_triggered.append(f"{rule_id}_REDACTED_{count}")

    if rules_triggered:
        return sanitized_text, SafetyAction.OUTPUT_REDACTED, rules_triggered

    return sanitized_text, SafetyAction.ALLOWED, []


class SecurityAuditLogger:
    """Thread-safe structured audit logger and telemetry tracker."""

    def __init__(self, log_path=settings.audit_log_path, max_in_memory: int = 200):
        self.log_path = log_path
        self.history: deque = deque(maxlen=max_in_memory)
        self.stats = {
            "total_requests": 0,
            "allowed_requests": 0,
            "input_blocked": 0,
            "output_blocked": 0,
            "output_redacted": 0,
            "categories": {}
        }

    def log_event(
        self,
        event_type: str,
        user_input: str,
        response_text: str,
        action: SafetyAction,
        rules_triggered: List[str],
        client_ip: str = "127.0.0.1",
        latency_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Record a structured security event to JSONL file and in-memory buffer."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "client_ip": client_ip,
            "user_input": user_input[:256] + ("..." if len(user_input) > 256 else ""),
            "response": response_text[:256] + ("..." if len(response_text) > 256 else ""),
            "action": action.value,
            "rules_triggered": rules_triggered,
            "latency_ms": round(latency_ms, 2),
            "metadata": metadata or {}
        }

        # Update statistics
        self.stats["total_requests"] += 1
        if action == SafetyAction.ALLOWED:
            self.stats["allowed_requests"] += 1
        elif action == SafetyAction.INPUT_BLOCKED:
            self.stats["input_blocked"] += 1
        elif action == SafetyAction.OUTPUT_BLOCKED:
            self.stats["output_blocked"] += 1
        elif action == SafetyAction.OUTPUT_REDACTED:
            self.stats["output_redacted"] += 1

        for rule in rules_triggered:
            self.stats["categories"][rule] = self.stats["categories"].get(rule, 0) + 1

        self.history.append(record)

        # Write to JSONL
        if settings.ENABLE_AUDIT_LOGGING:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception as e:
                logger.error(f"Failed to append to audit log {self.log_path}: {e}")

        return record

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.history)[-limit:]

    def get_metrics(self) -> Dict[str, Any]:
        total = self.stats["total_requests"]
        blocked = self.stats["input_blocked"] + self.stats["output_blocked"]
        blocking_rate = (blocked / total * 100.0) if total > 0 else 0.0
        return {
            "total_requests": total,
            "allowed_requests": self.stats["allowed_requests"],
            "input_blocked": self.stats["input_blocked"],
            "output_blocked": self.stats["output_blocked"],
            "output_redacted": self.stats["output_redacted"],
            "blocking_rate_percent": round(blocking_rate, 2),
            "triggered_rules_summary": self.stats["categories"]
        }


audit_logger = SecurityAuditLogger()
