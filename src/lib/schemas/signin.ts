import { z } from 'zod';
import { emailSchema, passwordSchema } from './fields';

export const SignInSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});
export type SignInInput = z.infer<typeof SignInSchema>;