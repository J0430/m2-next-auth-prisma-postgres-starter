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

## Files Touched

| File / Folder | Action | Notes |
|---------------|--------|-------|
| `.github/workflows/ci.yml` | Modified | Generate Prisma Client before coverage and set local E2E `NEXTAUTH_URL` / `APP_URL` |
| `prisma/schema.prisma` | Modified | Added `AdminMfaLegacyExemption` model mapped to the immutable snapshot table |
| `tests/security-ci-config.test.ts` | Modified | Locked the CI clean-runner generation and E2E origin contracts |
| `tests/gated-registration-security-verification.test.ts` | Modified | Uses committed packet/research evidence instead of ignored cursor-task files |
| `scripts/built-auth-golden-path.ts` | Modified | Reports callback status and redirect location when credentials are rejected |
| `docs/incidents/` | Updated | Added P038 and updated CI incident status/evidence |
| `README.md`, `CHANGELOG.md` | Updated | Documented CI repairs and Vercel Hobby cron blocker |

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
- The Vercel failure is not source-code-fixable without changing product
  cadence: the linked project is on Hobby and the repo declares a one-minute
  cron.

## Validation

```bash
pnpm prisma:generate                 # passed
pnpm prisma:validate                 # passed
pnpm exec vitest run tests/security-ci-config.test.ts  # 12/12 passed
pnpm exec vitest run tests/gated-registration-security-verification.test.ts  # 20/20 passed
pnpm exec vitest run tests/migration-readiness.test.ts  # 35/35 passed
pnpm exec vitest run tests/gated-registration-link-routes.test.ts  # 19/19 passed
pnpm test:coverage                   # 571/571 passed across 42 files
pnpm typecheck                       # passed
pnpm lint                            # passed
```

Full disposable-PostgreSQL migration-readiness could not be run locally because
Docker is unavailable and the installed Homebrew `libpq` tools do not include
the `postgres` server binary required by `initdb`.
