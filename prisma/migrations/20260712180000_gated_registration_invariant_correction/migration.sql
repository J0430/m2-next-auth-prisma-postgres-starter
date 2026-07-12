-- Corrects TASK-016 invite-digest and admin-capability invariants without rewriting migration history.
SET lock_timeout = '5s';

DELETE FROM "public"."verification_tokens" AS older
USING "public"."verification_tokens" AS newer
WHERE older."identifier" = newer."identifier"
  AND (older."expires", older."token") < (newer."expires", newer."token");

CREATE UNIQUE INDEX "verification_tokens_identifier_key"
  ON "public"."verification_tokens"("identifier");

ALTER TABLE "public"."invites"
  ADD CONSTRAINT "chk_invites_token_hash_length"
  CHECK (octet_length("tokenHash") = 32);

ALTER TABLE "public"."users"
  ADD COLUMN "adminBootstrapCompletedAt" TIMESTAMP(3);

ALTER TABLE "public"."admin_mfa_factors"
  ADD COLUMN "lastUsedStep" BIGINT;

CREATE TABLE "public"."admin_capability_grants" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "capability" TEXT NOT NULL,
  "grantedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revokedAt" TIMESTAMP(3),
  CONSTRAINT "admin_capability_grants_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "chk_admin_capability_grants_capability" CHECK ("capability" IN (
    'admin:invite:issue', 'admin:invite:revoke', 'admin:user:create', 'admin:mfa:manage'
  )),
  CONSTRAINT "admin_capability_grants_userId_fkey" FOREIGN KEY ("userId")
    REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "admin_capability_grants_userId_capability_revokedAt_idx"
  ON "public"."admin_capability_grants"("userId", "capability", "revokedAt");

CREATE UNIQUE INDEX "admin_capability_grants_active_unique"
  ON "public"."admin_capability_grants"("userId", "capability")
  WHERE "revokedAt" IS NULL;

CREATE UNIQUE INDEX "admin_mfa_factors_one_pending_totp_per_user"
  ON "public"."admin_mfa_factors"("userId")
  WHERE "status" = 'PENDING' AND "kind" = 'TOTP';

-- Transitional, immutable snapshot: only legacy invalid admins present at expand time.
CREATE TABLE "public"."admin_mfa_legacy_exemptions" (
  "userId" TEXT NOT NULL PRIMARY KEY,
  CONSTRAINT "admin_mfa_legacy_exemptions_userId_fkey" FOREIGN KEY ("userId")
    REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO "public"."admin_mfa_legacy_exemptions" ("userId")
SELECT candidate."id" FROM "public"."users" AS candidate
WHERE candidate."role" = 'ADMIN'
  AND (candidate."mfaEnrolledAt" IS NULL OR NOT EXISTS (
    SELECT 1 FROM "public"."admin_mfa_factors" AS factor
    WHERE factor."userId" = candidate."id" AND factor."status" = 'ACTIVE'
  ));

-- Freeze the expand-time snapshot. Runtime roles may remove a repaired identity,
-- but no principal can extend or rewrite the exemption set through DML.
CREATE OR REPLACE FUNCTION "public"."reject_admin_mfa_legacy_exemption_mutation"()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '55000',
    MESSAGE = 'admin MFA legacy exemptions are an immutable migration snapshot';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "admin_mfa_legacy_exemptions_immutable"
BEFORE INSERT OR UPDATE ON "public"."admin_mfa_legacy_exemptions"
FOR EACH STATEMENT EXECUTE FUNCTION "public"."reject_admin_mfa_legacy_exemption_mutation"();

REVOKE INSERT, UPDATE, TRUNCATE ON "public"."admin_mfa_legacy_exemptions" FROM PUBLIC;

CREATE OR REPLACE FUNCTION "public"."enforce_admin_mfa_capability"()
RETURNS trigger AS $$
DECLARE
  candidate_user_id TEXT;
  previous_user_id TEXT;
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    candidate_user_id := COALESCE(NEW."id", OLD."id");
    previous_user_id := candidate_user_id;
  ELSE
    IF TG_OP <> 'DELETE' THEN
      candidate_user_id := NEW."userId";
    END IF;
    IF TG_OP <> 'INSERT' THEN
      previous_user_id := OLD."userId";
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "public"."users" AS candidate
    WHERE (candidate."id" = candidate_user_id OR candidate."id" = previous_user_id)
      AND candidate."role" = 'ADMIN'
      AND NOT EXISTS (
        SELECT 1 FROM "public"."admin_mfa_legacy_exemptions" AS exemption
        WHERE exemption."userId" = candidate."id"
      )
      AND (
        candidate."mfaEnrolledAt" IS NULL
        OR NOT EXISTS (
          SELECT 1
          FROM "public"."admin_mfa_factors" AS factor
          WHERE factor."userId" = candidate."id"
            AND factor."status" = 'ACTIVE'
        )
      )
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '23514',
      CONSTRAINT = 'chk_admin_mfa_capability',
      MESSAGE = 'ADMIN requires mfaEnrolledAt and at least one ACTIVE AdminMfaFactor';
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER "users_admin_mfa_capability"
AFTER INSERT OR UPDATE OF "role", "mfaEnrolledAt" ON "public"."users"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "public"."enforce_admin_mfa_capability"();

CREATE CONSTRAINT TRIGGER "admin_mfa_factors_admin_capability"
AFTER INSERT OR UPDATE OR DELETE ON "public"."admin_mfa_factors"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "public"."enforce_admin_mfa_capability"();
