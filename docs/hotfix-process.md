# Hotfix Process

## Severity Levels

| Level | Description | Examples | SLA |
|-------|-------------|----------|-----|
| **P0** | Crypto failure or data leak | Plaintext written to disk, key leaked in logs, decryption produces wrong data | Fix in 48h, immediate Play Store patch |
| **P1** | Crash or feature-blocking bug | App crash on import, biometric loop, documents disappear | Fix in 1 week, standard release |
| **P2** | UX or minor issue | Layout glitch, slow preview, confusing error message | Backlog for V1.1 |

## P0 Hotfix Procedure

1. **Assess:** Confirm the vulnerability and its scope
2. **Branch:** Create `hotfix/v1.0.X` from the latest release tag
   ```bash
   git checkout -b hotfix/v1.0.1 v1.0.0
   ```
3. **Fix:** Apply the minimal fix (no feature work)
4. **Test:** Run the full hardening test suite + the specific regression test
5. **Bump:** Run `scripts/bump-version.sh patch`
6. **Tag:** `git tag v1.0.1`
7. **Build:** Signed AAB with production keystore
8. **Release:** Upload to Play Store with expedited review (if available)
9. **Notify:** Inform all beta testers / users via Play Store release notes
10. **Post-mortem:** Document root cause and prevention in `docs/postmortems/`

## P1 Fix Procedure

1. **Branch:** Fix on `main` or a feature branch
2. **Test:** Unit tests + relevant integration tests
3. **Bump:** `scripts/bump-version.sh patch`
4. **Tag and release:** Standard release process
5. **Timeline:** Within 1 week of report

## P2 Fix Procedure

1. **Triage:** Add to V1.1 milestone in GitHub Issues
2. **Fix:** Include in the next planned release
3. **No hotfix branch needed**

## Communication

| Severity | Internal | External |
|----------|----------|----------|
| P0 | Immediate Slack/email to all devs | Play Store release notes + GitHub Security Advisory |
| P1 | GitHub Issue + assignee | Play Store release notes |
| P2 | GitHub Issue | Included in next release notes |
