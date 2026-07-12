// Accessible invitation-only registration form with server-verified Turnstile.
"use client";

import { TurnstileWidget } from "@/features/auth/components/TurnstileWidget";
import type { RegistrationFormProps } from "./RegistrationForm.types";
import { useRegistrationForm } from "./useRegistrationForm";

export function RegistrationForm(props: RegistrationFormProps) {
  const registration = useRegistrationForm(props.csrfToken, props.callbackUrl);
  return (
    <main className="mx-auto max-w-xl p-6">
      <h1 className="text-2xl font-semibold">Create your invited account</h1>
      <p className="mt-2 text-gray-600">Enter the email address that received the invitation.</p>
      <form
        className="mt-6 grid gap-4"
        aria-label="Invitation registration"
        onSubmit={(event) => {
          event.preventDefault();
          registration.submit(event.currentTarget);
        }}
      >
        <label className="grid gap-1">
          <span>First name</span>
          <input name="firstname" autoComplete="given-name" className="rounded border p-2" />
        </label>
        <label className="grid gap-1">
          <span>Last name</span>
          <input name="lastname" autoComplete="family-name" className="rounded border p-2" />
        </label>
        <label className="grid gap-1">
          <span>Email</span>
          <input name="email" type="email" autoComplete="email" required className="rounded border p-2" />
        </label>
        <label className="grid gap-1">
          <span>Country code</span>
          <input name="country" minLength={2} maxLength={2} required autoComplete="country" className="rounded border p-2 uppercase" />
        </label>
        <label className="grid gap-1">
          <span>City</span>
          <input name="city" autoComplete="address-level2" className="rounded border p-2" />
        </label>
        <label className="grid gap-1">
          <span>Address</span>
          <input name="address" autoComplete="street-address" className="rounded border p-2" />
        </label>
        <TurnstileWidget
          siteKey={props.siteKey}
          nonce={props.nonce}
          resetKey={registration.resetKey}
          onToken={registration.setTurnstileToken}
        />
        {registration.message ? <p role="alert">{registration.message}</p> : null}
        <button
          type="submit"
          disabled={registration.pending || !registration.turnstileToken}
          className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50"
        >
          {registration.pending ? "Creating account…" : "Continue"}
        </button>
      </form>
    </main>
  );
}
