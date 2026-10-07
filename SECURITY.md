# Security Policy

## Supported Versions
| Version | Supported |
|---|---|
| v2.x | ✅ |
| v1.x | ❌ |

## Reporting a Vulnerability
Email: security@yourdomain.com (or open a private advisory on GitHub).

Please include:
- Affected endpoint
- Attack vector
- Reproduction steps
- Impact assessment

**Response SLA:** 48 hours acknowledgement, 7 days triage.

## Security Architecture
This project implements 12 OWASP-mapped defenses — see `/docs/attacks/`.
Audit log is hash-chained and verified on every CI run.
