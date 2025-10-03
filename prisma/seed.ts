/* eslint-disable no-console */
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const adminPass = await bcrypt.hash('admin123', 10);
  const userPass = await bcrypt.hash('user123', 10);

  await prisma.user.upsert({
    where: { email: 'admin@demo.io' },
    update: {
      role: 'ADMIN',
      profile: {
        upsert: {
          create: {
            country: 'GB',
            city: 'London',
            address: '221B Baker Street',
          },
          update: {
            country: 'GB',
            city: 'London',
            address: '221B Baker Street',
          },
        },
      },
    },
    create: {
      email: 'admin@demo.io',
      name: 'Admin Demo',
      role: 'ADMIN',
      password: adminPass,
      profile: {
        create: { country: 'GB', city: 'London', address: '221B Baker Street' },
      },
    },
  });

  await prisma.user.upsert({
    where: { email: 'user@demo.io' },
    update: {},
    create: {
      email: 'user@demo.io',
      name: 'User Demo',
      role: 'USER',
      password: userPass,
      profile: {
        create: { country: 'US', city: 'Miami', address: '1 Ocean Dr' },
      },
    },
  });

  console.log('Seeded admin@demo.io / admin123 and user@demo.io / user123');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });