import { z } from 'zod';

export const emailSchema = z.string().email('Invalid email');
export const passwordSchema = z.string().min(8, 'At least 8 characters');
