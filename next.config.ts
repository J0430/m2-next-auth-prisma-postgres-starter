import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'res.cloudinary.com', pathname: '/**' },
    ],
  },
  // Needed for Prisma in serverless runtimes
  serverExternalPackages: ['@prisma/client'],
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
