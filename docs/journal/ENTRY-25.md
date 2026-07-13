# ENTRY-25 - CI Release Follow-up Repairs

**Date:** 2026-07-13
**Type:** CI / Release Readiness
**Branch:** `feat/secure-registration`
**Version:** `1.9.1`
**PR:** `docs/pull-requests/PR-1.9.1.md`

---

## What I Did

Investigated the failing PR #32 checks after commit `502bf1f7`. The latest CI
logs showed three source-fixable failures and one external Vercel blocker:
coverage and E2E clean runners were missing generated Prisma Client state,
migration-readiness saw the raw SQL `admin_mfa_legacy_exemptions` table as
schema drift, and the built-auth E2E runtime was exercising a local app without
an explicit local NextAuth origin.

Follow-up CI logs showed three remaining clean-runner gaps: TASK-028 coverage
was reading ignored `docs/cursor-tasks` files, migration-readiness invoked a
TypeScript PrismaClient script before generating Prisma Client in that job, and
the built-auth credential callback error still lacked redirect detail.

A later migration-readiness run exposed that the real PostgreSQL
gated-registration integration was not part of pre-push. Reproducing it locally
also found local-only brittleness around trigger error metadata, raw timestamp
comparisons in non-UTC PostgreSQL sessions, non-run-scoped invite lookup hashes,
and outbox rows whose default due time raced the fixed test clock.

The next CI run still failed the pull-request `migration-readiness` job because
all replay-loser invite reuse attempts logged `auditPersisted: false`. The
durable audit write was wrapped in a 50ms outer deadline, which is too tight for
concurrent CI PostgreSQL writes. The audit now relies on Prisma transaction
wait/timeout budgets and the alert remains bounded separately.

The standalone local DB command also failed once with
`ADMIN_MFA_SECRET_KEYRING_MISSING` because pre-push exported the test keyring but
the package script did not. The package script now carries the same local-only
admin-MFA keyring fixture.

## Files Touched

| File / Folder | Action | Notes |
|---------------|--------|-------|
| `.github/workflows/ci.yml` | Modified | Generate Prisma Client before coverage and set local E2E `NEXTAUTH_URL` / `APP_URL` |
| `prisma/schema.prisma` | Modified | Added `AdminMfaLegacyExemption` model mapped to the immutable snapshot table |
| `tests/security-ci-config.test.ts` | Modified | Locked the CI clean-runner generation and E2E origin contracts |
| `tests/gated-registration-security-verification.test.ts` | Modified | Uses committed packet/research evidence instead of ignored cursor-task files |
| `package.json` | Modified | Added the test-only admin-MFA keyring fixture to the standalone DB integration command |
| `.husky/pre-push` | Modified | Runs gated-registration DB integration on local `auth_ci` before built-auth E2E |
| `scripts/built-auth-golden-path.ts` | Modified | Reports callback status and redirect location when credentials are rejected |
| `scripts/built-auth-golden-path.ts` | Modified | Refuses remote/non-disposable database URLs before fixture writes |
| `scripts/gated-registration-db-integration.ts` | Modified | Stabilized local PostgreSQL assertions, lookup hashes, and due outbox fixtures |
| `src/features/auth/server/invites/reuseEvidence.ts` | Modified | Replaced the 50ms audit race with a CI-safe Prisma transaction budget |
| `tests/gated-registration-invites.test.ts` | Modified | Locks the hardened reuse-audit transaction budget |
| `src/features/auth/server/outbox/db.ts` | Modified | Normalized outbox due/lease `Date` comparisons with `AT TIME ZONE 'UTC'` |
| `src/features/auth/server/outbox/maintenance.ts` | Modified | Normalized registration-session cleanup `Date` comparisons with `AT TIME ZONE 'UTC'` |
| `docs/incidents/` | Updated | Added P038 and updated CI incident status/evidence |
| `vercel.json` | Modified | Relaxed outbox fallback cron to once daily for Hobby deployment compatibility |
| `README.md`, `CHANGELOG.md` | Updated | Documented CI repairs and Vercel Hobby cron tradeoff |

## Decisions

- The legacy admin MFA exemption table remains a real database object because
  it is part of the additive migration's immutable bootstrap snapshot.
- Coverage should generate Prisma Client directly instead of relying on a
  different CI job's side effects.
- E2E should keep production-like build env but set local `NEXTAUTH_URL` and
  `APP_URL` for the downloaded app smoke test.
- Security verification tests must only depend on files present in a clean CI
  checkout; cursor-task working copies are ignored local planning artifacts.
- Migration-readiness must generate Prisma Client in its own job because it runs
  a TypeScript script that imports `@prisma/client`.
- Built-auth E2E must never trust the caller's default `.env`; it only writes
  fixtures to local `auth_e2e`.
- The Vercel failure is source-fixable only by changing product cadence on the
  fallback worker: Hobby supports a once-daily cron, so the repo now uses that
  cadence until the project moves to Pro/Enterprise or an external worker.
- The real PostgreSQL gated-registration integration belongs in pre-push because
  it catches migration-readiness behavior regressions that unit coverage cannot.
- Invite-reuse audit persistence is security evidence and should not use a
  50ms admission-style `Promise.race`; it needs a durable awaited transaction
  with bounded Prisma wait/timeout settings.
- Standalone DB integration commands should be self-contained for their local
  fixture env, especially when pre-push already depends on the same values.
- Raw SQL comparing Prisma `Date` parameters to PostgreSQL
  `timestamp without time zone` columns must normalize parameters with
  `AT TIME ZONE 'UTC'` to avoid local timezone drift.

## Validation

```bash
pnpm prisma:generate                 # passed
pnpm prisma:validate                 # passed
pnpm exec vitest run tests/security-ci-config.test.ts  # 12/12 passed
pnpm exec vitest run tests/gated-registration-security-verification.test.ts  # 17/17 passed
pnpm exec vitest run tests/gated-registration-invites.test.ts  # 20/20 passed
pnpm exec vitest run tests/migration-readiness.test.ts  # 35/35 passed
pnpm exec vitest run tests/gated-registration-link-routes.test.ts  # 19/19 passed
pnpm exec vitest run tests/gated-registration-outbox.test.ts  # 30/30 passed
DATABASE_URL=postgresql://manumurillo@localhost:5432/auth_ci pnpm test:db:gated-registration  # passed
pnpm test:coverage                   # 568/568 passed across 42 files
pnpm typecheck                       # passed
pnpm lint                            # passed
PRE_PUSH_ADMIN_DATABASE_URL="postgresql://manumurillo@localhost:5432/postgres" \
PRE_PUSH_DB_TEST_DATABASE_URL="postgresql://manumurillo@localhost:5432/auth_ci" \
PRE_PUSH_DATABASE_URL="postgresql://manumurillo@localhost:5432/auth_e2e" \
.husky/pre-push                      # passed
```
