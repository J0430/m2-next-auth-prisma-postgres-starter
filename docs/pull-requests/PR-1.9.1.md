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

The Vercel check is unblocked for the linked Hobby project by relaxing the
transactional outbox fallback cron to once daily.
The local pre-push hook now also runs the real PostgreSQL gated-registration
integration gate that was failing in CI, so migration-readiness failures are
caught before pushing.

## Files Changed

| File or Area | Action | Notes |
|--------------|--------|-------|
| `.github/workflows/ci.yml` | Modified | Coverage runs `pnpm prisma:generate`; E2E job exports local `NEXTAUTH_URL` and `APP_URL` |
| `prisma/schema.prisma` | Modified | Added `AdminMfaLegacyExemption` mapped to `admin_mfa_legacy_exemptions` |
| `tests/security-ci-config.test.ts` | Modified | Added assertions for coverage generation and E2E local origin |
| `tests/gated-registration-security-verification.test.ts` | Modified | Reads only committed packet/research docs in clean CI checkouts |
| `.husky/pre-push` | Modified | Runs gated-registration DB integration on local `auth_ci` before built-auth E2E |
| `scripts/built-auth-golden-path.ts` | Modified | Includes credential callback status and redirect location in failure output |
| `scripts/built-auth-golden-path.ts` | Modified | Refuses non-local `auth_e2e` database targets before writing fixtures |
| `scripts/gated-registration-db-integration.ts` | Modified | Makes local DB fixture timing and repeated runs deterministic |
| `package.json` | Modified | Supplies the test-only admin-MFA keyring fixture for standalone DB integration runs |
| `src/features/auth/server/invites/reuseEvidence.ts` | Modified | Gives durable invite-reuse audit writes a CI-safe Prisma transaction budget |
| `tests/gated-registration-invites.test.ts` | Modified | Locks the hardened invite-reuse audit transaction budget |
| `src/features/auth/server/outbox/db.ts`, `src/features/auth/server/outbox/maintenance.ts` | Modified | Normalize raw SQL `Date` comparisons with `AT TIME ZONE 'UTC'` |
| `vercel.json` | Modified | Uses a Hobby-compatible once-daily outbox fallback cron |
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
- Vercel cron cadence is now a deployment tradeoff: Hobby-compatible daily
  fallback now, once-per-minute polling only after a plan or worker change.
- Built-auth E2E is fail-closed against remote databases so local `.env` values
  cannot accidentally write golden-path fixtures to Neon or production.
- Invite-reuse evidence is security audit data, so the durable audit write must
  be awaited with a realistic Prisma transaction budget instead of racing a
  50ms admission-style deadline.
- The standalone `pnpm test:db:gated-registration` command must carry the same
  test-only admin-MFA keyring fixture as pre-push, otherwise it fails at the
  final stored-key readiness check despite the database behavior passing.
- Raw SQL that compares Prisma `Date` parameters with PostgreSQL
  `timestamp without time zone` columns must normalize with `AT TIME ZONE 'UTC'`
  to avoid local timezone drift in cleanup and claim predicates.

## Test Plan

- [x] `pnpm prisma:generate`
- [x] `pnpm prisma:validate`
- [x] `pnpm exec vitest run tests/security-ci-config.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-security-verification.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-invites.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-outbox.test.ts`
- [x] `DATABASE_URL=postgresql://manumurillo@localhost:5432/auth_ci pnpm test:db:gated-registration`
- [x] `pnpm exec vitest run tests/migration-readiness.test.ts`
- [x] `pnpm exec vitest run tests/gated-registration-link-routes.test.ts`
- [x] `pnpm test:coverage` - 568 tests across 42 files
- [x] `pnpm typecheck`
- [x] `pnpm lint`
- [x] `.husky/pre-push` with local `auth_ci` and `auth_e2e`
- [ ] GitHub `migration-readiness` clean-runner check
- [ ] GitHub `test-coverage` clean-runner check
- [ ] GitHub `e2e` clean-runner check

## Deployment Notes

The linked Hobby project should now accept the preview deployment. Transactional
outbox fallback latency is daily until the project upgrades or moves the worker
outside Vercel Cron.
