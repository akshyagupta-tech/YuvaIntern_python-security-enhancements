# Enterprise Application Hardening & Security Audit (Week 5)

**Intern:** Akshya Gupta  
**Track:** YuvaIntern — Junior Python Developer  
**Milestone:** Week 5 Task

## Architecture Overview
Production-grade application security hardening implementing defensive design patterns against OWASP Top 10 vulnerabilities:
- **Injection Defense:** DB-API parameterization neutralizing SQL Injection (CWE-89).
- **Process Isolation:** Direct argv passing via `subprocess.run(shell=False)` mitigating Command Injection (CWE-78).
- **Cryptographic Storage:** PBKDF2-HMAC-SHA256 key derivation with per-user dynamic salts (CWE-256).
- **Brute-Force Resistance:** In-memory sliding window rate limiting and account lockout.
- **Session Integrity:** Cryptographically generated URL-safe tokens with Time-To-Live (TTL) enforcement.

## Automated Verification Suite
```bash
python3 -m unittest -v test_security_audit.py
```
