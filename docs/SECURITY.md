# Security

**Version:** 1.9.1
**Last Updated:** 2026-07-12
**Current Status:** Security hardening controls implemented; production verification pending.

## Security Posture

The service has working security controls, but it must not currently be
described as attack-proof or fully production-hardened.

Security findings and remediation evidence are maintained privately. This
public document describes the current implemented controls and known risks.

## Implemented Controls

### Credentials

- Zod validation for credentials, signup, OTP, reset, and account actions.
- Normalized lowercase emails.
- bcrypt password hashing with cost factor 10.
- Credentials login requires `emailVerified`.
- PETSGRAM-origin accounts cannot use first-party credentials login.
- Generic duplicate-signup and password-reset responses reduce enumeration.

### Sessions

- NextAuth JWT session strategy.
- `NEXTAUTH_SECRET` requires at least 32 characters.
- Session cookies are HTTP-only and secure in production.
- OTP verification can create a session without another password submission.

### Email Verification

- Six-digit OTPs generated with `crypto.randomInt`.
- OTPs are stored as `HMAC-SHA256(code, OTP_HMAC_SECRET)` — bare SHA-256 no
  longer used.
- Configurable 10-minute default TTL and two-minute resend cooldown.
- Maximum five failed attempts per active token.
- Successful verification updates the user and deletes tokens transactionally.

### Password Reset

- Cryptographically random 256-bit reset tokens.
- Enumeration-resistant reset requests.
- Rate limits on request and token-consumption actions.
- Password update, token deletion, and database-session deletion occur in one
  transaction.

### OAuth/OIDC

- Exact registered redirect URI matching.
- HTTPS required outside localhost.
- Fragments rejected from redirect URIs.
- Scope validation against global and client allowlists.
- Client secrets stored as SHA-256 hashes and compared timing-safely.
- Authorization codes are random, short-lived, client-bound, redirect-bound,
  scope-bound, and optionally PKCE/nonce-bound.
- PKCE S256 is mandatory; `plain` is rejected at all validation points.
- Authorization-code consumption is atomic via conditional `updateMany`.
- RS256 access and ID tokens.
- All token responses carry `Cache-Control: no-store` and `Pragma: no-cache`.
- 429 responses carry `Retry-After` and a generic body; secrets never appear
  in limiter keys or logs.
- Token request bodies are Zod-validated (not cast with `as`).
- Public-key-only JWKS endpoint.
- Signed `id_token_hint` verification for logout.
- Allowlisted post-logout redirects.
- Google/GitHub social sign-in is limited to existing linked accounts whose
  owning user is `ACTIVE`.
- Unlinked social first sign-in and same-email silent account linking are
  denied before durable user/account persistence; adapter-level `createUser`
  and `linkAccount` backstops also fail closed.
- Social denial telemetry stores redacted provider/reason metadata only.

### Rate Limiting

- Distributed Upstash rate limiting is mandatory in production; fail-closed
  when Upstash is unavailable.
- `/oauth/token` and `/oauth/userinfo` are now rate-limited with independent
  per-IP and per-client/token-fingerprint buckets.
- IP extraction uses Vercel-injected headers validated with `node:net`;
  forwarded headers are not trusted outside Vercel in production.
- Seven-policy rate-limit map covers: credentials sign-in, signup, OTP
  verification, OTP resend, password-reset request, password-reset consumption,
  OAuth token exchange, UserInfo, and account mutation actions.

### Registration

- Self-service signup disabled in production via
  `SELF_SERVICE_REGISTRATION_ENABLED=false`.
- Transactional email delivery is handled by an internal outbox worker with
  fail-closed bearer-secret auth, admission limiter consumption, claim-token
  fencing, encrypted invite payloads, key-version decrypt support, and raw invite
  tokens emitted only in `/invite#token=...` fragments.

### HTTP and Data Layer

- CSP with `frame-ancestors 'none'`.
- HSTS in production.
- `X-Frame-Options: DENY`.
- `X-Content-Type-Options: nosniff`.
- Strict-origin Referrer Policy.
- Prisma parameterized queries; no application raw SQL found.
- Environment files are ignored by Git.

### Supply Chain and Secrets

- CI has a blocking `pnpm audit --audit-level=high` job (full dependency tree
  and production-only); zero HIGH/CRITICAL advisories required to pass.
- Full-history gitleaks secret scan is a blocking CI job.
- `SKIP_ENV_VALIDATION` removed from `vercel.json` and CI; full env validation
  runs on every production build.
- Seed data contains no known demo passwords and prints no secrets; the seed
  script refuses to run in production without
  `SEED_CONFIRMATION=DEVELOPMENT_ONLY`.

## Active Risks

### High Priority

- **Auth.js/NextAuth v5 migration:** NextAuth v4 is in maintenance mode. No
  security patches will be issued for v4 after its maintenance window closes.
- **bcrypt cost 10:** Below the intended hardening target; bcrypt 12+ and a
  migration strategy are planned.
- **Password-reset tokens stored directly:** Tokens are not hashed before
  persistence.
- **JWT validation gaps:** Header algorithm, issuer, audience, and runtime
  payload shape are not fully validated on every verification path.
- **Session lifecycle:** Max-age on `id_token_hint` and session expiry review
  are pending.

### Operational Gaps

- Turnstile verification helpers exist, but the public registration runtime has not consumed them yet.
- Explicit social account linking is implemented with authenticated CSRF-protected
  start routes, hash-only state, S256 PKCE, exact current-session generation
  binding, provider-subject identity, and transactional session invalidation.
  Provider-dashboard and production-browser verification remain pending.
- No structured application logger.
- No Sentry/error-tracking integration.
- No request correlation IDs or alerting.
- No coverage thresholds, E2E tests, or health endpoint.
- Invitation-only registration is partially implemented; the schema, invite lifecycle, transactional outbox worker, atomic invite registration service, and admission controls exist, and the signup kill switch (`SELF_SERVICE_REGISTRATION_ENABLED=false`) remains the production guard until the remaining public surfaces ship.
- Pairwise subjects not yet implemented.

## Control Matrix

| Area | Current (1.9.1) | Required Next State |
|------|-----------------|---------------------|
| Registration | Kill switch plus schema, invite lifecycle, transactional outbox worker, and admission controls | Invite/allowlist runtime gate |
| Account linking | Explicit state+PKCE linking implemented locally; email ignored and prior sessions invalidated | Provider-dashboard and production-browser proof |
| Rate limits | Upstash mandatory, OAuth endpoints covered, seven admission dimensions implemented | Consumer wiring for remaining runtime routes, logout limiting |
| PKCE | S256 required, plain rejected | — (complete) |
| Auth code use | Atomic conditional update | — (complete) |
| OTP storage | HMAC-SHA256 with server secret | — (complete) |
| Password hashing | bcrypt 10 | bcrypt 12+ and migration strategy |
| Dependencies | Blocking audit gate, 0 HIGH/CRITICAL | Ongoing maintenance |
| Secrets | Full-history gitleaks in CI | Ongoing |
| Observability | Console logs | Pino + request IDs + Sentry |
| Testing | 42 files, 572 tests | Coverage thresholds + Playwright |
| Session lifecycle | 30-day JWT | Max-age review, rotation |

## Account Linking

Google and GitHub no longer opt into Auth.js dangerous email account linking.
An OAuth callback can sign in only when the provider identity already has an
`Account` row linked to an `ACTIVE` user. A matching email alone does not link
accounts, and an unlinked first social sign-in is denied generically before user
or account persistence.

The Prisma adapter is wrapped so `createUser` and `linkAccount` fail closed if a
future callback path reaches persistence unexpectedly. Explicit user-approved
linking uses a dedicated both-factor ceremony outside NextAuth's normal sign-in callback.

## Subjects and Privacy

The OIDC subject is currently `User.id` for all clients. It is stable, but it
allows relying parties to correlate the same user.

Planned policy:

- existing client integrations retain public subjects;
- new clients default to pairwise subjects;
- credentials remain central and are never duplicated per app;
- per-app access is modeled with membership records.

Email remains a separate correlation vector whenever the `email` scope is
granted.

## Rate-Limited Paths

Currently rate-limited:

- credentials sign-in;
- signup;
- OTP verification;
- OTP resend;
- password-reset request;
- password-reset consumption;
- OAuth token exchange (per-IP + per-client/token-fingerprint buckets);
- UserInfo (per-IP + per-token-fingerprint buckets);
- account mutation actions.

Not currently rate-limited:

- logout.

All rate-limited paths use distributed Upstash buckets. The limiter is
fail-closed in production: a missing or unreachable Upstash instance blocks
the request rather than falling back to a process-local map.

## Environment and Secrets

The runtime schema is `src/lib/env.ts`; `.env.example` mirrors its keys.

Production-required values (enforced by env schema; build fails if absent):

- `DATABASE_URL`
- `NEXTAUTH_SECRET`
- `NEXTAUTH_URL` or `AUTH_URL`
- `OAUTH_JWT_PRIVATE_KEY`
- `OAUTH_JWT_PUBLIC_KEY`
- `OTP_HMAC_SECRET`
- `RESEND_API_KEY`
- `RESEND_FROM`
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`
- `TURNSTILE_SECRET_KEY`
- `TURNSTILE_EXPECTED_HOSTNAME`
- `TURNSTILE_EXPECTED_ACTION`
- `INTERNAL_WORKER_AUTH_SECRET`
- `QSTASH_URL`, `QSTASH_TOKEN`
- `INVITE_DELIVERY_ENCRYPTION_KEYS` and `INVITE_DELIVERY_KEY_VERSION`
- `INVITE_DELIVERY_KEY_VERSION`
- `ADMIN_MFA_SECRET_ENCRYPTION_KEYS`
- `ADMIN_MFA_SECRET_KEY_VERSION`
- `ADMIN_ELEVATION_MAX_AGE_SECONDS`

`OAUTH_JWT_PRIVATE_KEY`, `OAUTH_JWT_PUBLIC_KEY`, `OTP_HMAC_SECRET`,
`UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, and the
admission/invite/Admin-MFA secrets above are required fields in the production
env schema; the build fails without them.
`SKIP_ENV_VALIDATION` has been removed from `vercel.json` and CI.

Never store or log:

- plaintext passwords;
- OTP codes in production;
- reset tokens;
- authorization codes;
- access/ID tokens;
- OAuth client secrets;
- private signing keys.

## Incident and Release Process

Security regressions, test regressions, build failures, and production auth
exposure require an incident file before fixes begin.

An active security incident closes only after:

1. security-hardening changes are merged;
2. gated registration is merged;
3. CI passes;
4. production deployment succeeds;
5. credentials, OTP, OAuth, UserInfo, and logout golden paths are verified.

## Reporting a Vulnerability

Do not open a public issue containing exploit details or secrets. Contact the
repository owner privately with:

- affected endpoint or flow;
- reproduction steps;
- expected and actual behavior;
- impact assessment;
- suggested mitigation when available.
