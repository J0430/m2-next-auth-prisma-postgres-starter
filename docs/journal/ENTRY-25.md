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

## Files Touched

| File / Folder | Action | Notes |
|---------------|--------|-------|
| `.github/workflows/ci.yml` | Modified | Generate Prisma Client before coverage and set local E2E `NEXTAUTH_URL` / `APP_URL` |
| `prisma/schema.prisma` | Modified | Added `AdminMfaLegacyExemption` model mapped to the immutable snapshot table |
| `tests/security-ci-config.test.ts` | Modified | Locked the CI clean-runner generation and E2E origin contracts |
| `docs/incidents/` | Updated | Added P038 and updated CI incident status/evidence |
| `README.md`, `CHANGELOG.md` | Updated | Documented CI repairs and Vercel Hobby cron blocker |

## Decisions

- The legacy admin MFA exemption table remains a real database object because
  it is part of the additive migration's immutable bootstrap snapshot.
- Coverage should generate Prisma Client directly instead of relying on a
  different CI job's side effects.
- E2E should keep production-like build env but set local `NEXTAUTH_URL` and
  `APP_URL` for the downloaded app smoke test.
- The Vercel failure is not source-code-fixable without changing product
  cadence: the linked project is on Hobby and the repo declares a one-minute
  cron.

## Validation

```bash
pnpm prisma:generate                 # passed
pnpm prisma:validate                 # passed
pnpm exec vitest run tests/security-ci-config.test.ts  # 12/12 passed
pnpm exec vitest run tests/gated-registration-link-routes.test.ts  # 19/19 passed
pnpm test:coverage                   # 572/572 passed across 42 files
pnpm typecheck                       # passed
pnpm lint                            # passed
```

Full disposable-PostgreSQL migration-readiness could not be run locally because
Docker is unavailable and the installed Homebrew `libpq` tools do not include
the `postgres` server binary required by `initdb`.
