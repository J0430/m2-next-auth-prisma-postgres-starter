# PR-1.9.1 - Repair CI Release Follow-up Gates

**Journal:** `ENTRY-25`
**Branch:** `feat/secure-registration`
**Version:** `1.9.1`
**Date:** `2026-07-13`
**Status:** Local verification complete; GitHub clean-runner verification pending

---

## Summary

This follow-up repairs the PR #32 CI failures that were visible after commit
`502bf1f7`. It removes clean-runner assumptions from coverage, reconciles Prisma
schema parity with the additive admin MFA legacy-exemption table, and gives the
downloaded production build a local NextAuth origin during E2E smoke testing.
It also removes ignored cursor-task files from TASK-028 security evidence,
generates Prisma Client in migration-readiness before the TypeScript readiness
script runs, and makes built-auth credential rejection logs actionable.

The Vercel check remains externally blocked: the linked `manumu-auth` project is
on the Hobby plan, while `vercel.json` declares a one-minute cron for the
transactional outbox worker.

## Files Changed

| File or Area | Action | Notes |
|--------------|--------|-------|
| `.github/workflows/ci.yml` | Modified | Coverage runs `pnpm prisma:generate`; E2E job exports local `NEXTAUTH_URL` and `APP_URL` |
| `prisma/schema.prisma` | Modified | Added `AdminMfaLegacyExemption` mapped to `admin_mfa_legacy_exemptions` |
| `tests/security-ci-config.test.ts` | Modified | Added assertions for coverage generation and E2E local origin |
| `tests/gated-registration-security-verification.test.ts` | Modified | Reads only committed packet/research docs in clean CI checkouts |
| `scripts/built-auth-golden-path.ts` | Modified | Includes credential callback status and redirect location in failure output |
| `docs/incidents/INCIDENT-P038-ci-built-auth-nextauth-origin.md` | Created | Tracks the distinct E2E built-auth origin rejection |
| `README.md`, `CHANGELOG.md`, `docs/journal/ENTRY-25.md` | Updated | Living docs and release handoff synchronized |

## Architecture Notes

- The migration-created legacy exemption table is intentionally visible to
  Prisma schema parity even though runtime code treats it as an immutable SQL
  snapshot.
- E2E still uses the production-like build environment from `build-bundle`; the
  local origin is scoped to the E2E job.
- Migration-readiness now generates Prisma Client inside its own job so
  `scripts/admin-mfa-key-readiness.ts` can import `@prisma/client` in a clean
  runner.
- TASK-028 evidence is sourced from committed packet/research docs, not ignored
  cursor-task planning files.
- Vercel cron cadence is a deployment-plan decision, not a CI implementation
  bug.

## Test Plan

- [x] `pnpm prisma:generate`
- [x] `pnpm prisma:validate`
- [x] `pnpm exec vitest run tests/security-ci-config.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-security-verification.test.ts`
- [x] `pnpm exec vitest run tests/migration-readiness.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-link-routes.test.ts`
- [x] `pnpm test:coverage` - 571 tests across 42 files
- [x] `pnpm typecheck`
- [x] `pnpm lint`
- [ ] GitHub `migration-readiness` clean-runner check
- [ ] GitHub `test-coverage` clean-runner check
- [ ] GitHub `e2e` clean-runner check

## Deployment Notes

Before Vercel can pass on the linked Hobby project, either upgrade the project
to a plan that supports once-per-minute cron jobs or change the outbox fallback
cron to a once-daily schedule and accept the product tradeoff.
