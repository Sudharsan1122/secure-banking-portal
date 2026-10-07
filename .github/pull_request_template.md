## Summary
<!-- What does this PR do? -->

## Related Jira Story
<!-- e.g., SBP-42 -->

## Type of Change
- [ ] Feature
- [ ] Bug fix
- [ ] Security fix
- [ ] Refactor
- [ ] Docs

## Security Checklist
- [ ] All user input is validated server-side
- [ ] SQL uses prepared statements (no string concat)
- [ ] Output is encoded (htmlspecialchars / textContent)
- [ ] CSRF token included in all state-changing requests
- [ ] No secrets committed (.env excluded)
- [ ] No new dependencies without security review
- [ ] Audit logging added for security-relevant action
- [ ] Attack regression test added/updated
- [ ] Hash chain still valid after tests

## Testing
- [ ] `php tests/run_all.php` passes
- [ ] `php tests/attacks/run_attack_tests.php` passes
- [ ] Manual verification on localhost

## Screenshots (if UI)
