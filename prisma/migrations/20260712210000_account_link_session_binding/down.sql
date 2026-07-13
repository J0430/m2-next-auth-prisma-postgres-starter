-- Reverses only the additive account-link session-generation binding.
SET lock_timeout = '5s';

ALTER TABLE "public"."account_link_intents"
  DROP COLUMN IF EXISTS "sessionVersion";
