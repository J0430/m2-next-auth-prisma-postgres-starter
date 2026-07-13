# Auth Libraries

- `email/provider.ts` sends verification email through Resend.

Email delivery fails closed when Resend is not configured in every environment;
verification codes and recipient details are never written to fallback logs.
