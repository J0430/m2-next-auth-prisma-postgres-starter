// Sends a standalone Resend smoke-test message without exposing provider payloads.
import 'dotenv/config';
import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY!);

(async () => {
  const { error } = await resend.emails.send({
    from: process.env.RESEND_FROM!,
    to: ['youraddress@provider.com'],
    subject: 'Resend test',
    text: 'Hello from a standalone test.',
  });
  if (error) {
    console.error("email_smoke_test_failed", { code: "EMAIL_SMOKE_TEST_FAILED" });
    process.exitCode = 1;
    return;
  }
  console.log("email_smoke_test_succeeded", { code: "EMAIL_SMOKE_TEST_SUCCEEDED" });
})();
