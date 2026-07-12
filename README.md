# ManuMu Studio Authentication

Central authentication and OAuth/OIDC service for ManuMu Studio applications.

**Version:** 1.9.1
**Runtime:** Next.js 15 App Router · TypeScript 5.9 · NextAuth v4 · Prisma 6 · PostgreSQL
**Production URL:** [auth.manumustudio.com](https://auth.manumustudio.com)

## Current Capabilities

- Credentials sign-in with bcrypt password hashing.
- Google and GitHub sign-in through NextAuth for already-linked active accounts.
- Six-digit OTP email verification with resend cooldown and auto-login.
- Enumeration-resistant password-reset request flow.
- JWT sessions with user ID and role claims.
- Profile, password, connected-account, onboarding, and account-deletion UI.
- OAuth client registry with exact redirect URI and allowed-origin lists.
- Authorization Code flow with consent, mandatory PKCE S256, access tokens, and ID tokens.
- OIDC discovery, JWKS, UserInfo, and RP-initiated logout.
- Prisma migrations for PostgreSQL and Neon-compatible deployment.
- Invitation-only registration foundation: account status lifecycle (INACTIVE/ACTIVE/SUSPENDED/DELETED), invite lifecycle service with hash-only token storage, atomic invite registration and activation service, QStash-ready transactional email outbox worker with claim-token fencing and encrypted invite delivery, immutable audit events, registration-session handles, credential-backed admin TOTP elevation with explicit capability grants, Cloudflare Turnstile verification, shared admission helpers, and seven-surface rate-limit wiring.

## Security Controls

The following hardening controls are active in production:

- Upstash Redis rate limiting is required and fail-closed; the app refuses to start without it.
- Admission helpers add shared Turnstile verification, CSRF/parity helpers, and independent limiter dimensions for registration, invite redemption, login, password reset, OTP verify, fragment exchange, and admin operations.
- Invitation email delivery uses an internal worker route with fail-closed bearer-secret auth, admission limiter wiring, claim-token fencing, encrypted invite payloads, and fragment-only invite links.
- Social sign-in hardening: unlinked OAuth first sign-in and silent same-email account linking are denied. Account settings now provide an explicit, provider-bound linking ceremony; stale social-only sessions reauthenticate through an existing linked provider before starting a separate link.
- PKCE S256 is mandatory for every authorization request; `plain` is rejected.
- Authorization codes are consumed atomically, preventing replay races.
- Verification OTPs are stored as HMAC-SHA256 keyed with `OTP_HMAC_SECRET`.
- Self-service signup is disabled in production via `SELF_SERVICE_REGISTRATION_ENABLED=false`.
- CI enforces a blocking dependency audit (`pnpm audit --audit-level=high`) and a full-history secret scan.

Remaining work includes production provider callback configuration and browser
proof for explicit account linking, plus bcrypt cost increase, observability,
and pairwise subjects. See [Security](docs/SECURITY.md).

Historical security review records live in `docs/audits/` and `docs/incidents/`.

## Architecture

```text
Relying-party application
  -> /oauth/authorize
  -> ManuMu session / credentials / social provider
  -> authorization code
  -> /oauth/token
  -> RS256 access token + optional ID token
  -> JWKS / UserInfo verification
```

Existing relying parties use the same public `sub` (`User.id`). Pairwise
subjects are researched for new clients but are not implemented.

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [API contract](docs/api/openapi.yaml)
- [Roadmap](docs/roadmap/ROADMAP.md)

## Project Structure

```text
src/
├── app/
│   ├── (public)/                 # Public authentication entry
│   ├── (auth)/                   # Verify, reset, onboarding
│   ├── api/auth/                 # NextAuth and OTP APIs
│   ├── api/account/link/         # Dedicated explicit-link start/callback routes
│   ├── api/internal/             # Internal worker endpoints
│   ├── dashboard/                # Protected account management
│   ├── oauth/                    # Authorize, token, UserInfo, logout
│   ├── .well-known/              # OIDC discovery
│   └── jwks.json/                # Public signing keys
├── components/ui/                # Shared UI components
├── features/
│   ├── account/                  # Profile and account settings
│   └── auth/
│       ├── lib/
│       │   ├── email/                # Email provider helper
│       │   └── turnstile/            # Cloudflare Turnstile verification
│       └── server/
│           ├── actions/              # Server actions: sign-in, sign-up, reset
│           ├── admission/            # CSRF, enumeration-parity, admission types
│           ├── invites/              # Invite lifecycle: issue, lookup, redeem, revoke
│           ├── linking/              # Provider-bound state/PKCE account-link ceremony
│           ├── oauth/                # OAuth/OIDC authorization, token, claims, PKCE
│           ├── outbox/               # Transactional email outbox worker and crypto
│           ├── providers/            # NextAuth provider configuration
│           ├── reset/                # Password-reset flow
│           ├── social/               # Social sign-in gate and gated Prisma adapter
│           └── verify/               # OTP verification flow
└── lib/                          # Env, Prisma, rate limits, validation

prisma/
├── schema.prisma              # Includes invitation-only registration models
└── migrations/                 # Includes reversible gated-registration foundation SQL

tests/                          # Vitest suites, including schema/security invariants

docs/
├── api/                          # API contracts
├── audits/                       # Point-in-time audit reports
├── incidents/                    # Active/resolved incidents
├── research/                     # Research artifacts
├── roadmap/                      # Current execution plan
├── journal/                      # Historical feature entries
└── pull-requests/                # Historical PR records
```

## Local Setup

Prerequisites:

- Node.js 20 or newer
- pnpm 9.12.3
- PostgreSQL

```bash
pnpm install --frozen-lockfile
cp .env.example .env.local
pnpm prisma:generate
pnpm prisma:migrate
pnpm dev
```

Use pnpm only; npm/yarn are not supported.

## Environment

Required in all environments:

- `DATABASE_URL`
- `NEXTAUTH_SECRET` (minimum 32 characters)
- `NEXTAUTH_URL` or `AUTH_URL`

Required for OAuth/OIDC token issuance:

- `OAUTH_JWT_PRIVATE_KEY`
- `OAUTH_JWT_PUBLIC_KEY`
- `OAUTH_JWT_KID` (optional)

Required in production:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`
- `OTP_HMAC_SECRET` (minimum 32 characters)
- `SELF_SERVICE_REGISTRATION_ENABLED` (must be `false`)
- `TURNSTILE_SECRET_KEY`
- `TURNSTILE_EXPECTED_HOSTNAME`
- `TURNSTILE_EXPECTED_ACTION`
- `INTERNAL_WORKER_AUTH_SECRET`
- `QSTASH_URL`, `QSTASH_TOKEN`
- `INVITE_DELIVERY_ENCRYPTION_KEYS` (versioned JSON keyring), `INVITE_DELIVERY_KEY_VERSION`
- `INVITE_DELIVERY_KEY_VERSION`
- `ADMIN_MFA_SECRET_ENCRYPTION_KEYS`
- `ADMIN_MFA_SECRET_KEY_VERSION`
- `ADMIN_ELEVATION_MAX_AGE_SECONDS` (must be `300`)

Required for email delivery:

- `RESEND_API_KEY`
- `RESEND_FROM`

See [.env.example](.env.example) and [Deployment](docs/DEPLOYMENT.md).

## Commands

```bash
pnpm dev
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm prisma:validate
pnpm prisma:migrate
pnpm prisma:deploy
```

Current limitations:

- `pnpm lint` verifies without mutation; use `pnpm lint:fix` for explicit fixes.
- Current suite: 42 Vitest files / 572 tests.
- Coverage thresholds and Playwright E2E tests are not configured.
- The `smoke` script targets `/api/healthz`, which will be implemented during
  the account-linking parity work.

See [Testing](docs/TESTING.md) and [Contributing](CONTRIBUTING.md).

## Documentation Policy

Living documents describe the current codebase and must be synchronized in
every feature branch:

- `README.md`
- `CHANGELOG.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/api/openapi.yaml`
- `docs/roadmap/`
- relevant feature READMEs

Audits, incidents, journal entries, and merged PR documents are point-in-time
records and are not rewritten to make historical claims match current code.
