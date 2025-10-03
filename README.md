# M2 Auth & Profiles — Next.js + Prisma + Postgres (+ Chakra)

[![CI](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/ci.yml)
[![Deploy](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/vercel.yml/badge.svg)](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/vercel.yml)

A focused Next.js starter with **Credentials sign-in/sign-up**, **Prisma + Postgres**, and **Chakra UI**. Built with the **App Router**, **TypeScript**, **Zod** validation, and a clean **server/client boundary**.

> OAuth providers + NextAuth wiring can be enabled later (already planned). Current UI uses server actions with a unified result shape.

---

## 🚀 Features

- **Auth (current)**: Credentials sign-in/sign-up via server actions
- **DB**: Prisma ORM + PostgreSQL (Neon-ready)
- **UI**: Chakra UI, responsive layout
- **Validation**: Zod schemas with shared field rules
- **Types**: Full TS, unified `ActionResult` contract
- **DX**: Clear server/client boundary, Providers split
- **Prisma**: Migrations + optional seeding

---

## 🧪 Demo Users (if seeded)

- **Admin**: `admin@demo.io` / `admin123`
- **User**: `user@demo.io` / `user123`

> Run `pnpm db:seed` to create these users (see below).

---

## ⚡ Quick Start

### Prereqs
- Node 20+
- pnpm

### 1) Install
```bash
pnpm i

2) Environment

Copy .env.example to .env.local and fill in values:

# Database
DATABASE_URL="postgresql://user:password@host:5432/db?sslmode=require"

# Auth (for future NextAuth wiring)
NEXTAUTH_SECRET="dev-only-secret"
NEXTAUTH_URL="http://localhost:3000"
# Optional fallback also supported by env.ts:
# AUTH_URL="http://localhost:3000"


Server-only env parsing lives in src/lib/env.ts (Zod validated). Real secrets are ignored by Git; only .env.example is tracked.

3) Database
pnpm prisma:generate
pnpm prisma:migrate
pnpm db:seed     # optional demo users

4) Dev
pnpm dev


Open http://localhost:3000

📁 Project Structure (key parts)
src/
  app/
    layout.tsx         # Server component root
    providers.tsx      # Client-only Chakra provider
    page.tsx           # Demo: opens Auth modal w/ initialTab
  components/
    auth/
      AuthModal/       # Unified modal (Sign in / Sign up)
      AuthLayout/      # Switches form by initialTab
      SignInForm/
      shared/
    registration/
      SignupForm/
  lib/
    auth/
      signin.ts        # Server action: sign-in
      signup.ts        # Server action: sign-up
      types.ts         # Shared ActionResult type
    schemas/           # Zod: fields.ts, signin.ts, signup.ts
    env.ts             # Server-only env loader (Zod)
    prisma.ts          # Prisma client

🔒 Unified Action Result
export type ActionResult =
  | { ok: true }
  | { ok: false; errors: { formErrors?: string[]; fieldErrors?: Record<string, string[]> } };


Both actions (signinAction, registerUser) return this shape. Forms branch on ok and show errors.formErrors?.[0] when present.

🔧 Scripts
pnpm dev              # run locally
pnpm build            # production build
pnpm typecheck        # TS check

# Prisma
pnpm prisma:generate  # generate client
pnpm prisma:migrate   # create/apply migrations
pnpm prisma:deploy    # deploy migrations (prod)
pnpm db:seed          # seed demo users (optional)

🧭 Development Journal

See docs/DEVELOPMENT_JOURNAL.md
:

Entry 0 — Bootstrap

Entry 1 — Signup (UI + Server Action)

Entry 2 — Sign-in + Unified Actions + Env/Migration

🗂 Roadmap (next)

Sessions & NextAuth integration

OAuth providers (Google, etc.)

Tiny smoke tests for actions

Protected routes & role checks

Happy shipping! 🚀
