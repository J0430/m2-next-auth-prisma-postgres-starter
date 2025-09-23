# M2 Auth & Profiles — Next.js + Auth.js + Prisma + Postgres

[![CI](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/ci.yml)
[![Deploy](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/vercel.yml/badge.svg)](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/actions/workflows/vercel.yml)

A production-ready Next.js starter template with authentication, database management, and modern UI components. Built with Next.js 14+ App Router, TypeScript, Auth.js (NextAuth), Prisma, PostgreSQL, and Chakra UI.

## 🚀 Features

- **🔐 Authentication**: Auth.js with multiple providers (Credentials, Google, Facebook, Apple)
- **🗄️ Database**: Prisma ORM with PostgreSQL (Neon-ready)
- **🎨 UI**: Chakra UI with custom theme and responsive design
- **📝 Forms**: Zod validation for type-safe form handling
- **🛡️ Authorization**: Role-based access control (USER/ADMIN)
- **📱 Responsive**: Mobile-first design with modern UX
- **🔧 TypeScript**: Full type safety throughout the application
- **⚡ Performance**: Optimized with Next.js App Router
- **🧪 Testing**: CI/CD pipeline with GitHub Actions
- **📦 Monorepo**: Organized component structure with 4-file pattern

## 🎯 Demo Users

For testing purposes, the following demo users are seeded:

- **Admin**: `admin@demo.io` / `admin123`
- **User**: `user@demo.io` / `user123`

## 🚀 Quick Start

### Prerequisites

- Node.js 20+
- pnpm (recommended) or npm
- PostgreSQL database (local or hosted)

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd m2-next-auth-prisma-postgres-starter
pnpm install
```

### 2. Environment Setup

Copy the environment template and configure your variables:

```bash
cp .env.example .env.local
```

Update `.env.local` with your configuration:

```env
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/m2_auth_db"

# NextAuth.js
AUTH_SECRET="your-secret-key-here"
AUTH_URL="http://localhost:3000"

# OAuth Providers (optional)
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
# ... other OAuth providers
```

### 3. Database Setup

```bash
# Generate Prisma client
pnpm prisma:generate

# Run database migrations
pnpm prisma:migrate

# Seed the database with demo users
pnpm db:seed
```

### 4. Start Development Server

```bash
pnpm dev
```

Visit [http://localhost:3000](http://localhost:3000) to see the application.

## 📁 Project Structure

```
src/
├── app/                    # Next.js App Router pages
│   ├── (auth)/            # Authentication pages
│   │   ├── sign-in/       # Sign in page
│   │   └── sign-up/       # Sign up page
│   ├── (dashboard)/       # Protected dashboard
│   ├── profile/           # User profile management
│   ├── admin/             # Admin-only pages
│   │   └── users/         # User management
│   └── api/               # API routes
│       ├── auth/          # NextAuth configuration
│       └── healthz/       # Health check endpoint
├── components/            # Reusable components (4-file pattern)
│   ├── AuthProvider/      # Auth + Chakra providers
│   ├── Protected/         # Route protection wrapper
│   ├── FormField/         # Form input component
│   ├── OAuthButtons/      # OAuth provider buttons
│   └── Shell/             # Layout container
├── lib/                   # Utility libraries
│   ├── auth.ts           # NextAuth configuration
│   ├── prisma.ts         # Prisma client
│   ├── zodSchemas.ts     # Form validation schemas
│   ├── roles.ts          # Role-based access control
│   └── actions.ts        # Server actions
├── styles/               # Global styles
└── theme/                # Chakra UI theme configuration
```

## 🔧 Available Scripts

```bash
# Development
pnpm dev              # Start development server
pnpm build            # Build for production
pnpm start            # Start production server

# Code Quality
pnpm lint             # Run ESLint
pnpm typecheck        # Run TypeScript checks

# Database
pnpm prisma:generate  # Generate Prisma client
pnpm prisma:migrate   # Run database migrations
pnpm prisma:deploy    # Deploy migrations to production
pnpm db:seed          # Seed database with demo data

# Testing
pnpm smoke            # Test API health endpoint
```

## 🔐 Authentication & Authorization

### Supported Providers

- **Credentials**: Email/password authentication
- **Google**: OAuth 2.0 (requires Google Cloud Console setup)
- **Facebook**: OAuth 2.0 (requires Facebook Developer setup)
- **Apple**: OAuth 2.0 (requires Apple Developer setup)

### Role-Based Access Control

- **USER**: Standard user access
- **ADMIN**: Administrative access to user management

### Protected Routes

- `/dashboard` - Requires authentication
- `/profile` - Requires authentication
- `/admin/*` - Requires ADMIN role

## 🎨 UI Components

All components follow a consistent 4-file pattern:

- `ComponentName.tsx` - Main component logic
- `ComponentName.types.ts` - TypeScript interfaces
- `ComponentName.module.scss` - Styling (SCSS modules)
- `index.ts` - Export barrel

## 🗄️ Database Schema

The application uses Prisma with PostgreSQL and includes:

- **User**: User accounts with roles
- **Account**: OAuth provider accounts
- **Session**: User sessions
- **VerificationToken**: Email verification tokens

## 🚀 Deployment

### Vercel (Recommended)

1. Connect your GitHub repository to Vercel
2. Set environment variables in Vercel dashboard
3. Deploy automatically on push to main branch

### Environment Variables for Production

```env
DATABASE_URL="your-production-database-url"
AUTH_SECRET="your-production-secret"
AUTH_URL="https://your-domain.com"
# ... OAuth provider credentials
```

### Database Migration

For production deployments, run:

```bash
pnpm prisma:deploy
```

## 🔧 OAuth Provider Setup

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs:
   - `http://localhost:3000/api/auth/callback/google` (development)
   - `https://your-domain.com/api/auth/callback/google` (production)

### Facebook OAuth

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add Facebook Login product
4. Configure OAuth redirect URIs
5. Get App ID and App Secret

### Apple OAuth

1. Go to [Apple Developer](https://developer.apple.com/)
2. Create a new App ID
3. Configure Sign in with Apple
4. Create a Service ID
5. Generate private key and configure credentials

## 🧪 Testing

The project includes:

- **Health Check**: `GET /api/healthz`
- **Smoke Test**: `pnpm smoke`
- **Type Checking**: `pnpm typecheck`
- **Linting**: `pnpm lint`

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/your-username/m2-next-auth-prisma-postgres-starter/issues) page
2. Create a new issue with detailed information
3. Include steps to reproduce and expected behavior

## 🙏 Acknowledgments

- [Next.js](https://nextjs.org/) - React framework
- [Auth.js](https://authjs.dev/) - Authentication library
- [Prisma](https://prisma.io/) - Database ORM
- [Chakra UI](https://chakra-ui.com/) - Component library
- [Zod](https://zod.dev/) - Schema validation

---

**Happy coding! 🚀**
