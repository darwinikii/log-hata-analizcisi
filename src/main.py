import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Any, Dict, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from openai import OpenAI

logger = logging.getLogger("log_analizcisi")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(
    title="Akıllı Log ve Hata Analizcisi",
    version="1.0.0",
    description="Agent Pazaryeri v1.1 - LLM Tabanlı Log ve Hata Analiz Ajanı"
)

INJECTION_REGEXES = [
    re.compile(r'\btalimatlar[ıi]\s+unut\b', re.IGNORECASE),
    re.compile(r'\bönceki\s+talimatlar[ıi]\s+unut\b', re.IGNORECASE),
    re.compile(r'\bignore\s+(?:all\s+)?(?:previous\s+)?instructions\b', re.IGNORECASE),
    re.compile(r'\bdisregard\s+(?:all\s+)?(?:previous\s+)?instructions\b', re.IGNORECASE),
    re.compile(r'\bsistem\s+promptu(?:nu)?\b', re.IGNORECASE),
    re.compile(r'\bsystem\s+prompt\b', re.IGNORECASE),
    re.compile(r'\bgizli\s+ayarlar[ıi]\b', re.IGNORECASE),
    re.compile(r'\bapi\s+anahtar[ıi]n[ıi]\s+göster\b', re.IGNORECASE),
    re.compile(r'\boutput\s+(?:all\s+)?(?:env|llm_api_key|environment)\b', re.IGNORECASE),
    re.compile(r'\bprint\s+(?:the\s+)?(?:env|environment|llm_api_key)\b', re.IGNORECASE),
    re.compile(r'\breveal\s+(?:the\s+)?(?:system\s+prompt|secret|api\s+key)\b', re.IGNORECASE),
    re.compile(r'\bbypass\s+safety\b', re.IGNORECASE),
    re.compile(r'\bjailbreak\b', re.IGNORECASE),
    re.compile(r'\bact\s+as\s+(?:an?\s+)?unrestricted\b', re.IGNORECASE),
]


def verify_request_signature(request: Request, raw_body: bytes) -> None:
    """Gelen HTTP isteğinin HMAC-SHA256 imzasını ve zaman damgasını doğrular."""
    secret = os.environ.get("PLATFORM_SIGNING_SECRET", "").encode("utf-8")
    ts = (
        request.headers.get("X-Platform-Timestamp")
        or request.headers.get("x-platform-timestamp")
        or request.headers.get("x-signature-timestamp")
        or request.headers.get("x-timestamp")
    )
    sig = (
        request.headers.get("X-Platform-Signature")
        or request.headers.get("x-platform-signature")
        or request.headers.get("x-signature")
    )

    if not secret or not ts or not sig:
        raise HTTPException(status_code=401, detail="missing secret, timestamp or signature")

    try:
        ts_int = int(ts)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="invalid timestamp")

    if abs(time.time() - ts_int) > 300:
        raise HTTPException(status_code=401, detail="invalid timestamp")

    clean_sig = sig.removeprefix("sha256=")
    expected_with_ts = hmac.new(secret, f"{ts}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()
    expected_raw = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()

    if not (hmac.compare_digest(expected_with_ts, clean_sig) or hmac.compare_digest(expected_raw, clean_sig)):
        raise HTTPException(status_code=401, detail="invalid signature")


def mask_sensitive_data(text: str) -> Tuple[str, int]:
    """Log metnindeki e-posta, kredi kartı, telefon, TCKN, IP ve sırları maskeler."""
    total_masked = 0

    def mask_secret_val(m):
        nonlocal total_masked
        total_masked += 1
        return f"{m.group(1)}{m.group(2)}[MASKED_SECRET]"

    kv_secret_pattern = re.compile(
        r'(?i)\b(api[_-]?key|secret|token|password|passwd|authorization)(\s*[:=]\s*[\'"]?)([^\s,\'"]+)[\'"]?'
    )
    text = kv_secret_pattern.sub(mask_secret_val, text)

    def mask_bearer(m):
        nonlocal total_masked
        total_masked += 1
        return "Bearer [MASKED_SECRET]"

    text = re.sub(r'\bBearer\s+[a-zA-Z0-9_\-\.]{15,}\b', mask_bearer, text)

    def mask_key(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_SECRET]"

    text = re.sub(r'\b(?:sk|pk)_(?:live|test)_[a-zA-Z0-9_\-]{14,}\b', mask_key, text)

    def mask_ip(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_IP]"

    text = re.sub(
        r'\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b',
        mask_ip,
        text
    )

    def mask_email(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_EMAIL]"

    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', mask_email, text)

    def mask_card(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_CARD]"

    text = re.sub(r'\b(?:\d{4}[ -]){3}\d{1,7}\b', mask_card, text)
    text = re.sub(r'\b(?<!\[MASKED_)\d{13,19}\b', mask_card, text)

    def mask_tckn(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_TCKN]"

    text = re.sub(r'\b(?<!\[MASKED_)[1-9]\d{10}\b', mask_tckn, text)

    def mask_phone(m):
        nonlocal total_masked
        total_masked += 1
        return "[MASKED_PHONE]"

    text = re.sub(r'(?:\+90\s*|0)?5\d{2}[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}\b', mask_phone, text)

    return text, total_masked


def detect_prompt_injection(text: str) -> bool:
    """Girdi metninde prompt injection saldırı kalıplarını tespit eder."""
    return any(regex.search(text) for regex in INJECTION_REGEXES)


def extract_file_location(log_text: str) -> str:
    """Log veya çağrı yığınından gerçek dosya ve satır konumunu ayıklar."""
    py_matches = list(re.finditer(r'File\s+["\']([^"\']+)["\']\s*,\s*line\s+(\d+)', log_text))
    if py_matches:
        last = py_matches[-1]
        path = last.group(1).replace('\\', '/')
        return f"{path}:{last.group(2)}"

    js_tb = re.search(r'at\s+(?:[^\(\n\r]+\()?\s*([a-zA-Z0-9_\-./\\]+\.(?:js|jsx|ts|tsx|mjs|cjs)):(\d+)(?::(\d+))?\)?', log_text)
    if js_tb:
        path = js_tb.group(1).replace('\\', '/')
        line = js_tb.group(2)
        col = js_tb.group(3)
        return f"{path}:{line}:{col}" if col else f"{path}:{line}"

    java_tb = re.search(r'\(([a-zA-Z0-9_\-]+\.java):(\d+)\)', log_text)
    if java_tb:
        return f"{java_tb.group(1)}:{java_tb.group(2)}"

    std_loc = re.search(r'(?:in|at|file|from)\s+([a-zA-Z0-9_\-./\\]+\.(?:py|js|ts|tsx|jsx|java|go|rs|cpp|c|php|rb|cs|conf|yaml|yml)):(\d+(?::\d+)?)', log_text, re.IGNORECASE)
    if std_loc:
        path = std_loc.group(1).replace('\\', '/')
        return f"{path}:{std_loc.group(2)}"

    direct = re.search(r'\b([a-zA-Z0-9_\-./\\]+\.(?:py|js|ts|tsx|jsx|java|go|rs|cpp|c|php|rb|cs|conf|yaml|yml)):(\d+(?::\d+)?)\b', log_text)
    if direct:
        path = direct.group(1).replace('\\', '/')
        return f"{path}:{direct.group(2)}"

    return ""


def analyze_log_with_llm(sanitized_log: str, framework: str, lang: str, file_loc: str) -> Dict[str, Any]:
    """Sanitize edilmiş log metnini LLM kullanarak analiz eder ve yapılandırılmış JSON döner."""
    llm_base = os.environ.get("LLM_BASE_URL", "http://localhost:4000/v1").strip().rstrip("/")
    if not llm_base.endswith("/v1"):
        llm_base = f"{llm_base}/v1"
    llm_key = os.environ.get("LLM_API_KEY", "platform-fast-token").strip()
    model_name = os.environ.get("LLM_MODEL", "fast").strip()

    target_lang = "English" if lang == "en" else "Turkish"
    system_prompt = (
        f"You are a professional software engineer and log diagnostic agent for framework '{framework}'. "
        f"Analyze the provided sanitized log and output ONLY a valid JSON object with the following schema: "
        f'{{"error_type": "string", "severity": "low|medium|high|critical", "file_location": "string", "root_cause": "technical explanation in {target_lang}", "suggested_fix": "fix in {target_lang}"}}. '
        f"IMPORTANT: If there is no explicit file location in the log, file_location MUST be empty string. Never hallucinate paths."
    )

    client = OpenAI(base_url=llm_base, api_key=llm_key, timeout=60.0)
    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Log text to analyze:\n{sanitized_log}"}
        ],
        temperature=0.1,
        response_format={"type": "json_object"}
    )

    content = (response.choices[0].message.content or "{}").strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content, flags=re.DOTALL).strip()
    result = json.loads(content)

    final_file_location = file_loc if file_loc else ""

    sev = result.get("severity", "high")
    if sev not in ["low", "medium", "high", "critical"]:
        sev = "high"

    return {
        "error_type": str(result.get("error_type", "ApplicationError")),
        "severity": sev,
        "file_location": final_file_location,
        "root_cause": str(result.get("root_cause", "Hata analiz edildi.")),
        "suggested_fix": str(result.get("suggested_fix", "Log kaydındaki istisnayı kontrol edin."))
    }


@app.get("/health")
async def health_check():
    """Servis sağlık durumunu döner."""
    return {"status": "ok"}


@app.get("/")
async def root_info():
    """Servis temel meta verilerini döner."""
    return {
        "status": "ok",
        "agent": "log-hata-analizcisi",
        "version": "1.0.0"
    }


@app.post("/v1/invoke")
@app.post("/invoke")
@app.post("/")
async def invoke_agent(request: Request):
    """Gelen log analizi isteğini doğrular, maskeler, analiz eder ve standart zarfta yanıtlar."""
    raw_body = await request.body()

    verify_request_signature(request, raw_body)

    try:
        body = json.loads(raw_body.decode("utf-8") if raw_body else "{}")
    except Exception:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_input", "message": "Invalid JSON body"}}
        )

    operation = body.get("operation") or "analyze_log"

    tenant_id = (
        request.headers.get("X-Tenant-Id")
        or request.headers.get("x-tenant-id")
        or request.headers.get("X-Tenant-ID")
        or "anonymous"
    )
    request_id = (
        request.headers.get("X-Request-Id")
        or request.headers.get("x-request-id")
        or request.headers.get("X-Request-ID")
        or "unknown"
    )
    logger.info("request tenant_id=%s request_id=%s operation=%s", tenant_id, request_id, operation)

    if operation != "analyze_log":
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "unknown_operation", "message": f"Operation '{operation}' is not supported"}}
        )

    input_data = body.get("input") if isinstance(body.get("input"), dict) else body
    log_text = input_data.get("log_text")
    framework = str(input_data.get("framework") or "auto")

    if log_text is None:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_input", "message": "log_text is required"}}
        )
    if not isinstance(log_text, str):
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_input", "message": "log_text must be a string"}}
        )
    if not log_text.strip():
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_input", "message": "log_text cannot be empty"}}
        )
    if len(log_text) > 8000:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_input", "message": "log_text exceeds maximum length of 8000 characters"}}
        )

    config = body.get("config") or {}
    mask_pii = config.get("mask_pii", True)
    fail_on_severity = config.get("fail_on_severity", "critical")
    response_lang = config.get("response_language", "tr")

    if mask_pii:
        sanitized_log, masked_count = mask_sensitive_data(log_text)
    else:
        sanitized_log, masked_count = log_text, 0

    if detect_prompt_injection(log_text):
        output_data = {
            "error_type": "SecurityWarning:PromptInjectionAttempt",
            "severity": "high",
            "file_location": "",
            "root_cause": "Girdi içerisinde ajan talimatlarını değiştirmeye yönelik güvenlik ihlali (prompt injection) tespit edildi.",
            "suggested_fix": "Kullanıcı girdilerini loglamadan önce sanitize edin ve kontrol karakterlerini filtreleyin.",
            "sanitized_log": sanitized_log,
            "masked_pii_count": masked_count
        }
        return {
            "output": output_data,
            "status": "needs_review",
            "artifacts": [],
            "actions": [],
            "data": output_data,
            **output_data
        }

    file_loc = extract_file_location(sanitized_log)
    llm_analysis = analyze_log_with_llm(sanitized_log, framework, response_lang, file_loc)

    output_data = {
        "error_type": llm_analysis["error_type"],
        "severity": llm_analysis["severity"],
        "file_location": llm_analysis["file_location"],
        "root_cause": llm_analysis["root_cause"],
        "suggested_fix": llm_analysis["suggested_fix"],
        "sanitized_log": sanitized_log,
        "masked_pii_count": masked_count
    }

    sev = output_data["severity"]
    if sev == "critical":
        status = "fail"
    elif fail_on_severity == "high" and sev in ("high", "critical"):
        status = "fail"
    elif sev == "high":
        status = "needs_review"
    else:
        status = "ok"

    return {
        "output": output_data,
        "status": status,
        "artifacts": [],
        "actions": [],
        "data": output_data,
        **output_data
    }
