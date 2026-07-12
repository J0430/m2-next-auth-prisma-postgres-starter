// src/features/auth/server/registration/index.ts
// Public exports for invite-gated credentials registration.
export {
  REGISTRATION_CSRF_COOKIE_NAME,
  REGISTRATION_SESSION_COOKIE_NAME,
  registerWithInvite,
} from "./registerWithInvite";
export type { RegisterWithInviteInput, RegistrationResult } from "./registerWithInvite";
export { trustedCreateUser } from "./trustedCreateUser";
