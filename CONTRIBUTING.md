# Contributing to Secure Banking Portal

Thank you for contributing to Secure Banking Portal. Security is our first priority. All pull requests must pass our automated security-gated CI pipeline before merging.

---

## 🔒 Security Requirements for Code Changes

1. **Input Validation:** All incoming input must be canonicalized and validated with strict allow-lists.
2. **Prepared Statements:** SQL queries must use PDO prepared statements with native parameters. Zero string concatenation.
3. **Contextual Escaping:** All output reflected in HTML must be escaped using `safe_html()` / `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`.
4. **Anti-CSRF Tokens:** All state-changing endpoints (POST, PUT, DELETE) must validate a synchronizer CSRF token using timing-safe comparison (`hash_equals`).
5. **Session Scoping:** Never trust client-supplied identifiers (`user_id`, `account_id`) without verifying session ownership.
6. **Audit Logging:** Every security-relevant event must emit an entry via `log_security_event()` with cryptographic hash-chaining.
7. **No Hardcoded Secrets:** Never commit passwords, tokens, API keys, or credentials. Use `.env`.

---

## 🛠️ Local Verification Before Submitting a PR

Run these verification commands locally:

```bash
# 1. Syntax lint all PHP files
bash scripts/lint_php.sh

# 2. Scan for accidental secrets
bash scripts/check_secrets.sh

# 3. Run full master test suite (147/147 assertions)
php tests/run_all.php

# 4. Run 12 attack regression tests (46/46 assertions)
php tests/attacks/run_attack_tests.php

# 5. Verify cryptographic audit log hash chain
bash scripts/check_chain.sh
```

---

## 🚀 Pull Request Checklist

When opening a PR, complete the security checklist provided in the PR template:
- [x] All user input validated server-side
- [x] SQL uses prepared statements
- [x] Output encoded
- [x] CSRF token included
- [x] No secrets committed
- [x] Audit logging added
- [x] Attack regression test added/updated
- [x] Hash chain still valid after tests
