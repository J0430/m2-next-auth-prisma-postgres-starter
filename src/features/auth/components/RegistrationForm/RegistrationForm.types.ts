// Public props for the invitation-only registration form.
export interface RegistrationFormProps {
  csrfToken: string;
  nonce: string;
  siteKey: string;
  callbackUrl: string | null;
}
