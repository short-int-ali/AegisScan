# AegisScan – Cursor Implementation Instructions (MVP)

## 1. Role

You are implementing the **MVP of a passive web vulnerability scanner**.

This is a **read-only, non-intrusive security analysis tool**.
Do not add active exploitation features.

---

## 2. Core Rules (Must Follow)

- Passive scanning only
- No payload injection
- No authentication or session abuse
- No brute forcing
- No crawling or directory fuzzing
- Only predefined endpoint checks
- Clear, conservative findings

If a feature risks being intrusive, do NOT implement it.

---

## 3. Technology Stack

### Backend
- Python 3.11+
- FastAPI
- httpx (preferred) or requests
- Standard Python SSL libraries

### Frontend
- Minimal HTML/CSS (or simple React if needed)
- Focus on functionality, not styling

---

## 4. High-Level Architecture

Frontend  
→ `/scan` API endpoint  
→ Passive analysis modules  
→ Aggregated report object  
→ Response to frontend

---

## 5. API Requirements

### POST `/scan`

**Input**
```json
{
  "url": "https://example.com"
}
Output

json
Copy code
{
  "target": "https://example.com",
  "timestamp": "ISO-8601",
  "summary": {
    "high": 1,
    "medium": 2,
    "low": 3
  },
  "findings": [
    {
      "category": "Transport Security",
      "title": "Missing HSTS Header",
      "severity": "Medium",
      "description": "...",
      "remediation": "..."
    }
  ]
}
6. Modules to Implement
6.1 URL Normalization
Validate scheme

Follow redirects safely

Reject private/internal IPs

6.2 Transport Security Analyzer
Detect HTTPS usage

Identify HTTPS redirects

Inspect TLS certificate:

Expiry

Issuer

Validity

6.3 Security Header Analyzer
Check for:

Content-Security-Policy

Strict-Transport-Security

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Return:

Present / Missing

Weak configuration notes

6.4 Cookie Analyzer
Extract Set-Cookie headers

Check:

Secure

HttpOnly

SameSite

6.5 Passive Input Reflection Detection
Use benign markers only

No scripts or payloads

Only detect reflected input

6.6 Public Exposure Checker
Check ONLY:

/robots.txt

/sitemap.xml

/admin

/.env

Log status codes only.

7. Severity Assignment Rules
Missing HTTPS → High

Invalid TLS certificate → High

Missing CSP → Medium

Missing cookie security flags → Medium

Informational findings → Low

8. Reporting Rules
Every finding must include:

Title

Severity

Description

Remediation

Language must be professional and conservative

Avoid alarmist phrasing

9. Error Handling
Handle timeouts

Handle invalid URLs

Return structured error messages

Never crash the service

10. Explicit Non-Goals (DO NOT IMPLEMENT)
SQL injection testing

XSS payload execution

Authentication testing

CSRF attacks

Port scanning

Network fuzzing

11. Success Criteria
The MVP is complete when:

A URL can be scanned

Passive checks are executed

A structured vulnerability report is returned

No intrusive behavior exists