# AI Usage Note

This application integrates the Google Gemini API to translate CVSS scores and technical NVD vulnerability descriptions into executive-friendly summaries, business impact statements, and prioritized patching recommendations.

## 1. How AI Was Used & What It Helped With

- **Information Translation**: NVD descriptions are often written for security engineers and contain complex details about buffer overflows, memory access violations, or cryptographic states. The LLM translates these into clear business risks (e.g., "This could let an attacker access client records or bring down the online portal").
- **Prioritization Rationale**: The LLM synthesizes multidimensional factors (CVSS score, ease of network exploitation, business downtime) to write logical justifications explaining why a vulnerability should be addressed immediately or deferred.
- **Remediation Extraction**: When NVD descriptions lack explicit vendor patch instructions, Gemini constructs reasonable compensating controls (e.g., firewall rule adjustments, credential rotation, or process separation) as temporary workarounds.
- **Executive Summaries**: Aggregates scan numbers and key threats into professional board-level reporting structures, saving security directors hours of writing manually.

## 2. Common LLM Pitfalls & What Was Done to Address Them

- **JSON Inconsistency**: LLMs can occasionally return invalid JSON structures, markdown backticks block wraps, or skip critical keys.
  - *Mitigation*: Used the Gemini `response_mime_type="application/json"` setting to force standard JSON. In the Python backend, we catch JSON parse errors and fallback to rule-based risk summaries so the application never crashes.
- **Hallucinated CVE Exploit Status**: LLMs might claim a CVE is actively exploited in the wild when it is not.
  - *Mitigation*: We ensure NVD's verified public details (published date, CVSS score) are passed in as grounding context. We instruct the prompt to strictly limit assumptions to the provided data scope.
- **Unicode Encoding issues in PDF**: Emojis and smart quotes returned by the LLM can crash standard Latin-1 PDF compilers.
  - *Mitigation*: Implemented a clean text filter function (`clean_unicode_for_pdf`) that sanitizes all LLM outputs before they reach the FPDF2 generator.

## 3. Best Prompts Used

- **System Context Grounding**: *"You are an expert Cybersecurity Incident Responder and IT Risk Analyst..."* setting this standard persona significantly increased the professional quality of the output.
- **Structured JSON Schema Constraints**: Specifying the exact keys in the prompt:
  ```json
  {
    "business_impact": "...",
    "executive_explanation": "...",
    "remediation": "...",
    "priority_justification": "..."
  }
  ```
  Guaranteed high-quality parser compatibility.
