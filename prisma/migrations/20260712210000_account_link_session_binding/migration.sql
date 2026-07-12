-- Bind each account-link intent to the initiating JWT session generation.
ALTER TABLE "account_link_intents" ADD COLUMN "sessionVersion" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "account_link_intents" ALTER COLUMN "sessionVersion" DROP DEFAULT;
