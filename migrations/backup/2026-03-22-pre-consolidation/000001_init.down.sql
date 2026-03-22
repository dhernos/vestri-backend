DROP TRIGGER IF EXISTS "PasskeyCredential_set_updatedAt" ON "PasskeyCredential";
DROP TRIGGER IF EXISTS "OAuthAccount_set_updatedAt" ON "OAuthAccount";
DROP TRIGGER IF EXISTS "User_set_updatedAt" ON "User";

DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS "PasskeyCredential";
DROP TABLE IF EXISTS "OAuthAccount";
DROP TABLE IF EXISTS "VerificationToken";
DROP TABLE IF EXISTS "User";
