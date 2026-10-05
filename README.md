# 🛡️ Enterprise RAG Compliance Guardrails API

An enterprise-grade, asynchronous security middleware proxy built in **Python** and **FastAPI**. This microservice acts as an inline data-loss prevention (DLP) layer positioned between corporate user interfaces and public Large Language Models (LLMs) like OpenAI, Claude, or OpenRouter. It intercepts raw orchestration prompts, applies high-performance deterministic scrubbing models, and redacts sensitive parameters to enforce strict data-privacy constraints under standard **ISO 27001:2022** control compliance paradigms.

## 🏗️ Architectural Core & Capabilities

Standard corporate Retrieval-Augmented Generation (RAG) and agentic workflows are highly prone to accidental disclosures of internal configuration footprints or customer identities. This API mitigates risk at the transport layer before tokens leave the local network boundary:

*   **Deterministic PII Elimination Engine:** Implements pre-compiled compiled regex patterns to detect and mask multi-variate sensitive profiles including corporate emails, financial instruments (Credit Cards), and system access assets.
*   **Leak Prevention Guardrails:** Intercepts critical infrastructure phrases (e.g., core root keys or master credentials) to automatically trigger an HTTP 400 security isolation state rather than forwarding vulnerable payloads.
*   **Compliance-Validated Schemas:** Built entirely on top of strict `Pydantic` structural validation patterns to guarantee deterministic data logging frameworks.
*   **Asynchronous Processing Pipeline:** Uses high-throughput `FastAPI` and `Uvicorn` servers to optimize system throughput overhead down to a sub-millisecond execution lifecycle.

---

## 🛠️ System Components & Directory Layout

The application architecture isolates runtime logic away from execution artifacts:

```text
rag-guardrails-api/
├── .gitignore               # Excludes python local venv and temporary system state files
├── requirements.txt         # Core production dependency signatures
├── main.py                  # FastAPI routing infrastructure and regex validation policies
└── sanitized_output.json    # Written capture state showing verified audit output payloads
```

---

## ⚙️ Compilation & Local Deployment

Follow these sequential parameters to spin up the local microservice infrastructure daemon:

### 1. Configure the Virtual Runtime & Dependencies
Ensure your terminal environment is running a Python 3.10+ execution ring:
```bash
# Navigate to project root path
cd E:\rag-guardrails-api

# Initialize and launch the virtual environment layer
python -m venv venv
source venv/bin/activate  # Windows CMD alternative: venv\Scripts\activate

# Install the verified package configuration footprints
pip install -r requirements.txt
```

### 2. Boot Up the Security Gateway
Execute the primary entry point file to spin up the background loopback application proxy:
```bash
python main.py
```
The terminal log traces confirm port deployment:
```text
INFO:     Started server process [PID: 1422]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

---

## 🧪 Integration & Output Verification

### Local API Verification
While the background application process remains awake, execute a secure `POST` call from a separate console layer using structured prompt metrics containing unencrypted infrastructure leak signatures:

```cmd
curl -X POST "http://127.0.0" -H "Content-Type: application/json" -d "{\"user_id\": \"emp_1102\", \"prompt\": \"Analyze this error log containing api key sk_1234567890abcdefghij and alert admin@company.com immediately.\"}" -o sanitized_output.json
```

### Deterministic Audit Payload Result
The endpoint interceptor evaluates the payload, strips out vulnerable infrastructure identities automatically, and writes the following payload block directly into `sanitized_output.json`:

```json
{
  "original_prompt": "Analyze this error log containing api key sk_1234567890abcdefghij and alert admin@company.com immediately.",
  "sanitized_prompt": "Analyze this error log containing api key [REDACTED_API_CREDENTIAL] and alert [REDACTED_EMAIL] immediately.",
  "pii_detected": true,
  "blocked_entities": [
    "Email Address",
    "System Secret/API Key"
  ],
  "compliance_status": "PASSED_WITH_REDACTION"
}
```

---

## 🛡️ ISO 27001 Validation Matrix Alignment
This specific codebase layout satisfies and enforces several key controls defined under the latest global regulatory baselines:
*   **Control A.8.11:** Masking and masking architectures for strict data privacy constraints.
*   **Control A.8.12:** Prevention of unauthorized data leakage via standard system interface routes.
*   **Control A.8.23:** Automatic tracking, monitoring, and sanitization of clear-text system access keys.
