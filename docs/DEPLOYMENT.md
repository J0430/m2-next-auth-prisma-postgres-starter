# Deployment

**Version:** 1.9.1
**Target:** Vercel + Neon PostgreSQL

## Required Services

- Vercel project for `auth.manumustudio.com`
- Neon/PostgreSQL database
- Resend account and verified sender
- RSA key pair for OAuth/OIDC signing
- Upstash Redis (required in production — the app refuses to boot without it)
- QStash-compatible delivery for the internal transactional email outbox worker

## Required Environment Variables

### Core

- `DATABASE_URL`
- `NEXTAUTH_SECRET` (minimum 32 characters)
- `NEXTAUTH_URL` or `AUTH_URL`
- `APP_URL`

### OIDC Signing

- `OAUTH_JWT_PRIVATE_KEY` (PEM-encoded RSA private key)
- `OAUTH_JWT_PUBLIC_KEY` (PEM-encoded RSA public key)
- `OAUTH_JWT_KID` (optional)

### Email

- `RESEND_API_KEY`
- `RESEND_FROM`

### Rate Limiting (required in production)

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

### OTP Security (required in production)

- `OTP_HMAC_SECRET` (minimum 32 characters; generate with `openssl rand -base64 48`)

### Registration

- `SELF_SERVICE_REGISTRATION_ENABLED` — must be `false` in production for this release

### Invitation and Admission Controls (required in production)

- `TURNSTILE_SECRET_KEY`
- `TURNSTILE_EXPECTED_HOSTNAME`
- `TURNSTILE_EXPECTED_ACTION`
- `INTERNAL_WORKER_AUTH_SECRET`
- `QSTASH_URL` and `QSTASH_TOKEN`
- `INVITE_DELIVERY_ENCRYPTION_KEYS` (JSON map of numeric versions to 32-byte hex keys)
- `INVITE_DELIVERY_KEY_VERSION` (active write version retained in the keyring)
- `ADMIN_MFA_SECRET_ENCRYPTION_KEYS` (JSON version-to-32-byte-hex-key map)
- `ADMIN_MFA_SECRET_KEY_VERSION` (must exist in the keyring)
- `ADMIN_ELEVATION_MAX_AGE_SECONDS` — must be `300`

### Optional / Rate-Limit Tuning

- `RATE_LIMIT_MAX`
- `RATE_LIMIT_WINDOW_MINUTES`

### Seed / Development Only

- `SEED_ADMIN_PASSWORD`
- `SEED_USER_PASSWORD`
- `SEED_OAUTH_CLIENT_SECRET`
- `SEED_CONFIRMATION` — must equal `DEVELOPMENT_ONLY` for the seed to run

The seed creates no administrator. The exceptional `pnpm admin:mfa:bootstrap`
ceremony is governed by ADR-001: bind the exact canonical URL by SHA-256, use
loopback by default, and require the remote allow flag plus separate approval proof
for any non-loopback target. Password and approval secret are supplied through
`ADMIN_BOOTSTRAP_PASSWORD` and `ADMIN_BOOTSTRAP_APPROVAL_SECRET`, never argv.

### Platform (set automatically by Vercel)

- `VERCEL` — auto-injected; controls which IP-header trust strategy is active

See `.env.example` for a full annotated reference.

## Release-readiness preflight

The repository is the release contract. Before Preview or Production, configure
the GitHub `VERCEL_PROJECT_ID` variable plus `VERCEL_TOKEN` and optional
`VERCEL_TEAM_ID` secrets, then run the manual **Release readiness** workflow.
Locally, use:

```bash
RELEASE_TARGET=preview \
VERCEL_PROJECT_ID=<expected-project-id> \
VERCEL_TOKEN=<read-only-token> \
pnpm release:preflight
```

The command reads only project metadata and environment-variable names. It
fails on the wrong project, dashboard command drift, or missing Preview/
Production names and never prints values. Optional deployment provenance uses
`RELEASE_DEPLOYMENT_ID`, `RELEASE_GIT_REF`, and `RELEASE_GIT_SHA` together.

Release evidence follows this state ladder:
`planned → locally-implemented → committed → merged → deployed → production-verified`.
A local or CLI deployment never satisfies GitHub-backed release evidence.

## Pre-Deploy Checklist

Before deploying 1.9.1 to production:

- [ ] Generate and set `OTP_HMAC_SECRET` (≥32 characters, never reuse across environments)
- [ ] Generate and set dedicated `ACCOUNT_LINK_PKCE_SECRET` (≥32 characters; do not reuse OAuth client secrets)
- [ ] Create a separate GitHub OAuth App for account linking, set its callback to `/api/account/link/github/callback`, and configure `GITHUB_LINK_CLIENT_ID` / `GITHUB_LINK_CLIENT_SECRET`
- [ ] Configure Google callback `{APP_URL}/api/account/link/google/callback` in addition to the normal sign-in callback
- [ ] Configure GitHub callback `{APP_URL}/api/account/link/github/callback` in addition to the normal sign-in callback
- [ ] Verify Upstash Redis production credentials (`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`)
- [ ] Verify RSA signing keys (`OAUTH_JWT_PRIVATE_KEY`, `OAUTH_JWT_PUBLIC_KEY`) and correct issuer URL (`AUTH_URL`)
- [ ] Set `SELF_SERVICE_REGISTRATION_ENABLED=false` in Vercel environment
- [ ] Set Turnstile, internal-worker, invite-delivery, Admin-MFA keyring, and admin freshness environment variables
- [ ] Confirm the internal outbox worker destination is reachable at `/api/internal/outbox-email` and receives only opaque row-id QStash messages
- [ ] Rotate any previously-used seeded or shared credentials (seed passwords, OAuth client secrets)
- [ ] Confirm CI pipeline passes (lint, typecheck, tests, build, security audit) on the branch
- [ ] Confirm preview deployment is healthy

> **OTP invalidation note:** Changing `OTP_HMAC_SECRET` invalidates all outstanding verification OTPs stored before the change. Users in the middle of email verification must request a new code. Communicate this proactively if rotating the key outside of a new deployment.

## Deployment Sequence

```bash
pnpm install --frozen-lockfile
pnpm prisma:generate
pnpm prisma:validate
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm audit --audit-level=high
pnpm audit --prod --audit-level=high
```

CI separately applies every migration to disposable PostgreSQL, checks
`prisma migrate status`, and compares migration history with the Prisma schema.
Production `prisma migrate deploy` remains an authorized pipeline step that
runs before new code serves traffic; never run it from a developer laptop.
The Admin-MFA readiness step must also call `validateStoredAdminMfaKeyVersions`
against the deployment database before traffic, proving every stored factor version
exists in `ADMIN_MFA_SECRET_ENCRYPTION_KEYS`.

Vercel runs `pnpm prisma:generate && next build` automatically. `SKIP_ENV_VALIDATION` is no longer set; full environment validation runs on every build.

## Post-Deploy Verification Checklist

After deploying to production, verify the golden path before closing any incident:

- [ ] `/.well-known/openid-configuration` advertises `code_challenge_methods_supported: ["S256"]` (S256 only — no `plain`)
- [ ] Complete a valid S256 authorization-code flow end to end (authorize → token → UserInfo)
- [ ] Replay the authorization code and confirm it is rejected (`error: invalid_grant`)
- [ ] Submit a request to `/oauth/token` without a `code_challenge` field and confirm rejection
- [ ] Hit `/oauth/token` and `/oauth/userinfo` repeatedly and confirm 429 with `Retry-After` header
- [ ] Confirm all `/oauth/token` responses include `Cache-Control: no-store` and `Pragma: no-cache`
- [ ] Verify OTP resend and new-code flow (request a new OTP, verify the new code succeeds)
- [ ] Confirm that self-service signup returns a generic "registration unavailable" response
- [ ] Inspect application logs and confirm no secrets, tokens, or OTP codes appear
- [ ] Link Google and GitHub from Account Settings; verify cancellation/replay fail generically and all pre-link sessions are invalidated

## CI Environment

CI runs parallel lint/typecheck, coverage, build/bundle, migration, and security
jobs. The built-app health smoke test consumes the production build artifact.
Coverage thresholds and a 10 MiB `.next/static` budget are blocking. CI
generates an ephemeral RSA keypair; `SKIP_ENV_VALIDATION` is never set.

## Rollback

- Keep migrations backward-compatible whenever possible.
- Do not deploy destructive schema changes without a tested rollback or restoration procedure.
- For OAuth contract changes (especially PKCE requirements), verify relying-party compatibility before rolling out.
- If an auth regression reaches production, open or update an incident before attempting the fix.
- Rolling back past a `OTP_HMAC_SECRET` rotation invalidates any OTPs issued under the new secret.
