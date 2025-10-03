'use server';

import { z } from 'zod';
import { SignInSchema } from '@/lib/schemas/signin';
import { prisma } from '@/lib/prisma';
import { compare } from 'bcryptjs';
// import { signIn } from 'next-auth/react' // if/when you wire Credentials provider
import type { ActionResult } from './types';


export async function signinAction(formData: FormData): Promise<ActionResult> {
  const raw = Object.fromEntries(formData.entries());
  const parsed = SignInSchema.safeParse(raw);
  if (!parsed.success) {
    const flat = parsed.error.flatten();
    return {
      ok: false,
      errors: {
        formErrors: flat.formErrors?.length ? flat.formErrors : ['Invalid input'],
        fieldErrors: flat.fieldErrors,
      },
    };
  }

  const email = parsed.data.email.trim().toLowerCase();
  const password = parsed.data.password;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.password) {
    return { ok: false, errors: { formErrors: ['Invalid credentials'] } };
  }

  const valid = await compare(password, user.password);
  if (!valid) return { ok: false, errors: { formErrors: ['Invalid credentials'] } };

  // If using Auth.js credentials, you would do:
  // await signIn('credentials', { email, password, redirect: false });

  return { ok: true };
}