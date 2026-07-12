-- Reverses only the additive TASK-016 invariant correction.
SET lock_timeout = '5s';

DROP INDEX IF EXISTS "public"."verification_tokens_identifier_key";

DROP INDEX IF EXISTS "public"."admin_mfa_factors_one_pending_totp_per_user";
DROP TRIGGER IF EXISTS "admin_mfa_factors_admin_capability" ON "public"."admin_mfa_factors";
DROP TRIGGER IF EXISTS "users_admin_mfa_capability" ON "public"."users";
DROP FUNCTION IF EXISTS "public"."enforce_admin_mfa_capability"();
DROP TRIGGER IF EXISTS "admin_mfa_legacy_exemptions_immutable" ON "public"."admin_mfa_legacy_exemptions";
DROP FUNCTION IF EXISTS "public"."reject_admin_mfa_legacy_exemption_mutation"();
DROP TABLE IF EXISTS "public"."admin_mfa_legacy_exemptions";
DROP TABLE IF EXISTS "public"."admin_capability_grants";
ALTER TABLE "public"."admin_mfa_factors" DROP COLUMN IF EXISTS "lastUsedStep";
ALTER TABLE "public"."users" DROP COLUMN IF EXISTS "adminBootstrapCompletedAt";

ALTER TABLE "public"."invites"
  DROP CONSTRAINT IF EXISTS "chk_invites_token_hash_length";
