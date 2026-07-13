// Submits invite-bound registration and resets single-use challenge state.
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { registerUser } from "@/features/auth/server/actions";

export function useRegistrationForm(csrfToken: string, callbackUrl: string | null) {
  const router = useRouter();
  const [turnstileToken, setTurnstileToken] = useState("");
  const [resetKey, setResetKey] = useState(0);
  const [message, setMessage] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const submit = (form: HTMLFormElement) => {
    setMessage(null);
    const formData = new FormData(form);
    formData.set("csrfToken", csrfToken);
    formData.set("turnstileToken", turnstileToken);
    startTransition(async () => {
      const result = await registerUser(formData);
      setResetKey((value) => value + 1);
      if (!result.ok || !result.meta?.email) {
        setMessage("Unable to complete this request.");
        return;
      }
      const params = new URLSearchParams({ email: result.meta.email });
      if (callbackUrl) params.set("callbackUrl", callbackUrl);
      router.push(`/verify?${params.toString()}`);
    });
  };

  return { message, pending, resetKey, setTurnstileToken, submit, turnstileToken };
}
