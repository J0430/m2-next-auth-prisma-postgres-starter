import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  images: {
    // Prefer remotePatterns over deprecated images.domains
    remotePatterns: [
      { protocol: 'https', hostname: 'res.cloudinary.com', pathname: '/**' },
      // add more when you wire OAuth avatars later:
      // { protocol: 'https', hostname: 'lh3.googleusercontent.com', pathname: '/**' },
      // { protocol: 'https', hostname: 'platform-lookaside.fbsbx.com', pathname: '/**' },
      // { protocol: 'https', hostname: 's.gravatar.com', pathname: '/**' },
    ],
  },
  // Needed for Prisma in serverless runtimes
  serverExternalPackages: ['@prisma/client'],
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
