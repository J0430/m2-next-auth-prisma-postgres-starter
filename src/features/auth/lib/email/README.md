# Verification Email

`provider.ts` sends HTML and text OTP emails through Resend.

- Production: requires `RESEND_API_KEY` and `RESEND_FROM`.
- Development without Resend: delivery fails closed without logging message contents.
- SMTP, Facebook, and Apple providers are not implemented.
