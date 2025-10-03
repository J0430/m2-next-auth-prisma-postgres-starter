'use server';

import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/prisma';
import { SignUpSchema, type SignUpInput } from '@/lib/schemas/signup';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import type { ActionResult } from './types';

export async function registerUser(formData: FormData): Promise<ActionResult> {
  const raw = {
    firstname: formData.get('firstname')?.toString(),
    lastname: formData.get('lastname')?.toString(),
    email: formData.get('email')?.toString(),
    password: formData.get('password')?.toString(),
    repeatpassword: formData.get('repeatpassword')?.toString(),
    country: formData.get('country')?.toString(),
    city: formData.get('city')?.toString(),
    address: formData.get('address')?.toString(),
  };

  const parsed = SignUpSchema.safeParse(raw);
  if (!parsed.success) {
    const flat = parsed.error.flatten();
    return {
      ok: false,
      errors: {
        formErrors: flat.formErrors?.length ? flat.formErrors : [parsed.error.issues[0]?.message ?? 'Invalid form'],
        fieldErrors: flat.fieldErrors,
      },
    };
  }

  const data: SignUpInput = parsed.data;

  // Normalize defensively
  const email = data.email.trim().toLowerCase();
  const firstname = data.firstname?.trim();
  const lastname = data.lastname?.trim();
  const country = data.country?.toUpperCase();
  const city = data.city?.trim();
  const address = data.address?.trim();

  // Unique email guard
  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return { ok: false, errors: { formErrors: ['Email already registered'] } };

  const hash = await bcrypt.hash(data.password, 10);

  try {
    await prisma.user.create({
      data: {
        email,
        name: [firstname, lastname].filter(Boolean).join(' ').trim() || null,
        password: hash,
        profile: { create: { country, city, address } },
      },
    });
    return { ok: true };
  } catch (err: unknown) {
    // TS-safe narrowing for Prisma known request errors
    if (err instanceof PrismaClientKnownRequestError) {
      if (err.code === 'P2002') {
        return { ok: false, errors: { formErrors: ['Email already registered'] } };
      }
    }
    return { ok: false, errors: { formErrors: ['Unexpected error creating user'] } };
  }
}

// The two TypeScript lines you asked about
// A) registerUser has a typed return:
// export type ActionResult = { ok: true } | { ok: false; error: string };

// export async function registerUser(formData: FormData): Promise<ActionResult> { ... }

// This says: the function must always resolve to exactly one of two shapes:

// Success: { ok: true }

// Failure: { ok: false, error: string }

// Why it matters:

// If you forget to return error on a failure path, TS will complain.

// The FE can safely branch on ok with full autocomplete and no any.

// FE usage becomes clean:

// const res = await registerUser(fd);
// if (!res.ok) {
//   // res.error is guaranteed to exist and be a string
// }

// B) RegisterInput = z.infer<typeof RegisterSchema>
// export const RegisterSchema = z.object({ /* ... */ });
// export type RegisterInput = z.infer<typeof RegisterSchema>;

// z.infer takes your Zod schema and produces the TypeScript type for the parsed data.

// This means one source of truth: you define the rules once (Zod), and both runtime validation and compile-time types stay in sync.

// In the action:

// const parsed = RegisterSchema.safeParse(raw);
// if (!parsed.success) { /* handle */ }

// const data: RegisterInput = parsed.data; // strongly typed
// // data.email is string; data.country is string | undefined; etc.

// This avoids duplicating interfaces and eliminates drift between "what we validate" and "what we think the type is."
