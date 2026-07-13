// Defines SQL used by the disposable migration-readiness rehearsal.
export const TASK_016_FOUNDATION_DIRECTORY = 'prisma/migrations/20260620173500_gated_registration_foundation';
export const TASK_016_CORRECTION_DIRECTORY = 'prisma/migrations/20260712180000_gated_registration_invariant_correction';
export const TASK_023_LINK_BINDING_DIRECTORY = 'prisma/migrations/20260712210000_account_link_session_binding';

export const EMPTY_DATABASE_SQL = `SELECT (
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f', 'i', 'I', 'c'))
  + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_collation o JOIN pg_namespace n ON n.oid = o.collnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_conversion o JOIN pg_namespace n ON n.oid = o.connamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_ts_config o JOIN pg_namespace n ON n.oid = o.cfgnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_ts_dict o JOIN pg_namespace n ON n.oid = o.dictnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_ts_parser o JOIN pg_namespace n ON n.oid = o.prsnamespace
    WHERE n.nspname = 'public')
  + (SELECT count(*) FROM pg_ts_template o JOIN pg_namespace n ON n.oid = o.tmplnamespace
    WHERE n.nspname = 'public')
)`;

export const MIGRATION_CHECKSUM_SQL = `SELECT migration_name || E'\\t' || checksum
FROM "_prisma_migrations"
WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL
ORDER BY migration_name`;

export const ADMIN_MFA_RELEASE_READINESS_SQL = `SELECT
  (SELECT count(*) FROM public.users AS candidate
   WHERE candidate.role = 'ADMIN' AND (
     candidate."mfaEnrolledAt" IS NULL OR NOT EXISTS (
       SELECT 1 FROM public.admin_mfa_factors AS factor
       WHERE factor."userId" = candidate.id AND factor.status = 'ACTIVE'
     )
   ))::text || E'\\t' ||
  (SELECT count(*) FROM public.admin_mfa_legacy_exemptions)::text`;

export const PRESERVATION_FIXTURE_SQL = `BEGIN;
INSERT INTO public.users (
  id, email, "emailVerified", password, "passwordHash", "hasPasswordCredential", status, "updatedAt"
) VALUES (
  'task032-user', 'task032@example.invalid', '2026-01-01T00:00:00Z',
  'task032-password-hash', 'task032-password-hash', true, 'ACTIVE', CURRENT_TIMESTAMP
);
INSERT INTO public.accounts (id, "userId", type, provider, "providerAccountId")
VALUES ('task032-account', 'task032-user', 'oauth', 'task032-provider', 'task032-provider-account');
INSERT INTO public.oauth_clients (
  id, "clientId", "clientSecretHash", name, "redirectUris", "allowedOrigins", scopes, "updatedAt"
) VALUES (
  'task032-client', 'task032-client-id', 'task032-non-secret-hash', 'TASK-032 fixture',
  ARRAY['https://task032.example.invalid/callback'], ARRAY['https://task032.example.invalid'], ARRAY['openid'], CURRENT_TIMESTAMP
);
INSERT INTO public.oauth_authorization_codes (
  id, code, "clientId", "userId", "redirectUri", scopes, "expiresAt"
) VALUES (
  'task032-code', 'task032-code-value', 'task032-client-id', 'task032-user',
  'https://task032.example.invalid/callback', ARRAY['openid'], CURRENT_TIMESTAMP + INTERVAL '5 minutes'
);
COMMIT;`;

export const PRESERVATION_SQL = `SELECT json_build_object(
  'users', (SELECT md5(string_agg(id || ':' || coalesce("emailVerified"::text, ''), ',' ORDER BY id)) FROM public.users),
  'accounts', (SELECT md5(string_agg(id || ':' || provider || ':' || "providerAccountId", ',' ORDER BY id)) FROM public.accounts),
  'oauth_clients', (SELECT md5(string_agg(
    id || ':' || "clientId" || ':' || "clientSecretHash" || ':' || name || ':'
    || array_to_string("redirectUris", ',') || ':' || array_to_string("allowedOrigins", ',') || ':'
    || array_to_string(scopes, ','), ',' ORDER BY id
  )) FROM public.oauth_clients),
  'oauth_codes', (SELECT md5(string_agg(id || ':' || code || ':' || "userId", ',' ORDER BY id)) FROM public.oauth_authorization_codes)
)`;
