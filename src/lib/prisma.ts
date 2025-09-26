// src/lib/prisma.ts
import { PrismaClient } from '@prisma/client';

// Avoid creating multiple PrismaClient instances during dev HMR.
// In prod we keep a single instance per process.
const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    // log: ['query', 'info', 'warn', 'error'], // enable if needed
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

export default prisma;
