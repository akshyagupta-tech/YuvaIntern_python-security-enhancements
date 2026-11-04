# Enterprise Defensive Security & OWASP Hardening Suite

**Intern:** Akshya Gupta  
**Track:** YuvaIntern — Junior Python Developer  
**Milestone:** Week 5 Task

## Architecture Overview
The Week 5 application demonstrates defensive controls without executing attack
payloads: parameterized SQLite access, PBKDF2-HMAC-SHA256 password hashing,
Unicode-aware allow-list validation, argv-only subprocess calls with timeouts,
role-scoped sessions, token-bucket throttling, and redacted tamper-evident audit
events. The former vulnerable sample is now inert comparison data.

## Modules
- `crypto.py`: PBKDF2 password hashing, random salts, constant-time verification, and secret generation.
- `database.py`: Parameterized SQLite repository with no startup data deletion.
- `sanitizer.py`: Unicode normalization, markup removal, and field-specific allow-lists.
- `audit.py`: Recursive redaction and HMAC-linked JSON audit records.
- `auth.py`, `sessions.py`, and `rate_limiter.py`: Authentication orchestration, RBAC, TTL, and brute-force controls.
- `subprocess_runner.py`: Validated network target with fixed argv and an execution timeout.
- `security_checks.py`: AST-only checks for unsafe calls/imports and secret literals.
- `app.py`: Safe interactive diagnostics and authentication lab.
- `test_security.py`: Security regression suite; `test_security_audit.py` preserves facade behavior checks.

## Automated Verification Suite
```bash
python3 -m unittest discover -v
```

## Run the Web Lab
```bash
python3 -m pip install -r requirements.txt
streamlit run app.py
```
