import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# Initialize our Security Guardrail API
app = FastAPI(
    title="🛡️ RAG Compliance Guardrails API",
    description="Enterprise middleware to intercept prompts, strip PII, and enforce data privacy compliance boundaries."
)

# Input data schema validating enterprise system queries
class PromptRequest(BaseModel) :
    user_id: str = Field(..., description="Unique enterprise resource identification string.")
    prompt: str = Field(..., description="Raw text prompt heading to external foundational models.")

# Output data schema returning cleaned data metadata signatures
class GuardrailResponse(BaseModel):
    original_prompt: str
    sanitized_prompt: str
    pii_detected: bool
    blocked_entities: list[str]
    compliance_status: str

# Robust Regex compile matches for PII (Emails, Credit Cards, API Secret Keys)
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
API_KEY_REGEX = re.compile(r'(?:sk|AIza|ghp|secret)_[a-zA-Z0-9]{20,}')

@app.post("/api/v1/sanitize", response_model=GuardrailResponse)
async def sanitize_prompt(request: PromptRequest):
    """
    Intercepts corporate prompts, evaluates compliance risk, 
    and applies a redaction mask over sensitive structural boundaries.
    """
    original = request.prompt
    sanitized = original
    blocked = []
    pii_found = False

    # 1. Identify and redact matching Email entities
    if EMAIL_REGEX.search(sanitized):
        sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)
        blocked.append("Email Address")
        pii_found = True

    # 2. Identify and redact matching Credit Card profiles
    if CREDIT_CARD_REGEX.search(sanitized):
        sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_FINANCIAL_DATA]", sanitized)
        blocked.append("Credit Card Number")
        pii_found = True

    # 3. Identify and redact matching exposed API Tokens or Credentials
    if API_KEY_REGEX.search(sanitized):
        sanitized = API_KEY_REGEX.sub("[REDACTED_API_CREDENTIAL]", sanitized)
        blocked.append("System Secret/API Key")
        pii_found = True

    # 4. Strict Block Policy: If severe operational leaks are found, flag a compliance warn cycle
    compliance_signature = "PASSED_WITH_REDACTION" if pii_found else "CLEAN_COMPLIANT"
    
    # Simulating a strict block if an engineer attempts to pipe raw backend server variables explicitly
    if "root_password" in original.lower():
        raise HTTPException(
            status_code=400, 
            detail="⚠️ Security Intercept: Prompt contains absolute forbidden enterprise operational phrases."
        )

    return GuardrailResponse(
        original_prompt=original,
        sanitized_prompt=sanitized,
        pii_detected=pii_found,
        blocked_entities=blocked,
        compliance_status=compliance_signature
    )

if __name__ == "__main__":
    import uvicorn
    # Start the fast loopback enterprise application engine on local port 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)
