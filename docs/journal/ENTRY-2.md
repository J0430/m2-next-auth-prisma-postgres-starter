# Entry 2 — Sign-in, Unified Actions, Env & Migrations

Scope

Add Credentials sign-in form and server action with Zod validation.

Introduce unified ActionResult for both sign-in and sign-up.

Normalize inputs (email, country), and handle P2002 duplicate email.

Update .env.example for NEXTAUTH_SECRET and NEXTAUTH_URL.

Run latest Prisma migration and confirm seed users.

Files

Forms: src/components/auth/SignInForm/SignInForm.tsx, src/components/registration/SignupForm/SignupForm.tsx

Actions: src/lib/auth/signin.ts, src/lib/auth/signup.ts, src/lib/auth/types.ts

Schemas: src/lib/schemas/signin.ts, src/lib/schemas/signup.ts, src/lib/schemas/fields.ts

Env & Prisma: src/lib/env.ts, prisma/migrations/20251003141621_/migration.sql, prisma/seed.ts


