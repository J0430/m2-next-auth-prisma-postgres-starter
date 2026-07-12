// Enumeration-safe registration page backed only by an opaque HttpOnly handle.
import { headers } from "next/headers";

import { RegistrationForm } from "@/features/auth/components/RegistrationForm";

export const dynamic = "force-dynamic";

type RegisterPageProps = {
  searchParams: Promise<{ callbackUrl?: string }>;
};

export default async function RegisterPage({ searchParams }: RegisterPageProps) {
  const requestHeaders = await headers();
  const params = await searchParams;
  return (
    <RegistrationForm
      csrfToken={requestHeaders.get("x-registration-csrf") ?? ""}
      nonce={requestHeaders.get("x-nonce") ?? ""}
      siteKey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY ?? ""}
      callbackUrl={params.callbackUrl ?? null}
    />
  );
}
