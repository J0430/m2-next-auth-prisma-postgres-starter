import { z } from 'zod';

export const SignInSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export const RegisterSchema = z
  .object({
    firstname: z.string().trim().optional(),
    lastname: z.string().trim().optional(),
    email: z.string().email(),
    password: z.string().min(8),
    repeatpassword: z.string().min(8),
    country: z.string().length(2).optional(),
    city: z.string().min(2).max(120).optional(),
    address: z.string().min(3).max(500).optional(),
  })
  .refine((d) => d.password === d.repeatpassword, {
    message: 'Passwords must match',
    path: ['repeatpassword'],
  });

export const UpdateProfileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  image: z.string().url('Invalid image URL').optional().or(z.literal('')),
});

export type SignInInput = z.infer<typeof SignInSchema>;
export type RegisterInput = z.infer<typeof RegisterSchema>;
export type UpdateProfileInput = z.infer<typeof UpdateProfileSchema>;
