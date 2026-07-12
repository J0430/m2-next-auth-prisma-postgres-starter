// Public sign-in surface; account creation is available only through invitations.
"use client";

import { AnimatePresence } from "framer-motion";
import { signIn, useSession } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";

import AuthShell from "@/components/ui/AuthShell";
import EmailStep from "@/features/auth/components/steps/EmailStep";
import PasswordStep from "@/features/auth/components/steps/PasswordStep";
import { SignInSchema } from "@/lib/validation/signin";

type Step = "email" | "password";

export default function PublicSignInPage() {
  const { data: session, status, update } = useSession();
  const router = useRouter();
  const callbackUrl = useSearchParams().get("callbackUrl");
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const emailInputRef = useRef<HTMLInputElement>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const directionRef = useRef<"forward" | "backward">("forward");
  const [animate, setAnimate] = useState(false);

  useEffect(() => {
    if (status !== "authenticated" || !session?.user) return;
    if (callbackUrl) window.location.href = callbackUrl;
    else router.replace("/dashboard");
  }, [callbackUrl, router, session, status]);

  const transitionTo = (next: Step, direction: "forward" | "backward") => {
    directionRef.current = direction;
    setAnimate(true);
    setStep(next);
    setTimeout(() => setAnimate(false), 500);
  };

  const next = () => {
    setError(null);
    const parsed = SignInSchema.pick({ email: true }).safeParse({ email });
    if (!parsed.success) {
      setError("Please enter a valid email address");
      emailInputRef.current?.focus();
      return;
    }
    setEmail(email.trim().toLowerCase());
    transitionTo("password", "forward");
  };

  const submit = () => {
    setError(null);
    if (!password) {
      setError("Please enter your password");
      passwordInputRef.current?.focus();
      return;
    }
    startTransition(async () => {
      const result = await signIn("credentials", {
        redirect: false,
        email: email.trim().toLowerCase(),
        password,
      });
      if (result?.error) {
        setError(result.error === "RATE_LIMITED"
          ? "Too many requests. Please try again later."
          : "Invalid credentials. Please check your email and password.");
        passwordInputRef.current?.focus();
        return;
      }
      await update();
    });
  };

  if (status === "authenticated") return null;
  if (status === "loading") {
    return (
      <AuthShell title="Loading..." subtitle="Please wait" animateOnChange={false}>
        <div className="flex items-center justify-center py-12" role="status">Loading…</div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title={step === "email" ? "Sign in to ManuMu" : email}
      subtitle={step === "password" ? "Enter your password" : undefined}
      animateOnChange={animate}
      direction={directionRef.current}
    >
      <AnimatePresence mode="wait" custom={directionRef.current}>
        {step === "email" ? (
          <EmailStep
            email={email}
            error={error}
            isPending={pending}
            emailInputRef={emailInputRef}
            direction={directionRef.current}
            onEmailChange={(value) => { setEmail(value); setError(null); }}
            onNext={next}
          />
        ) : (
          <PasswordStep
            password={password}
            error={error}
            isPending={pending}
            passwordInputRef={passwordInputRef}
            direction={directionRef.current}
            onPasswordChange={(value) => { setPassword(value); setError(null); }}
            onSubmit={submit}
            onBack={() => { setPassword(""); setError(null); transitionTo("email", "backward"); }}
          />
        )}
      </AnimatePresence>
    </AuthShell>
  );
}
