'use client';

import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';
import InputField from '@/components/ui/InputField';
import NextButton from '@/components/ui/NextButton';
import { GoogleButton, GitHubButton } from '@/features/auth/components/ProviderButtons';
import type { EmailStepProps } from './EmailStep.types';
import styles from './EmailStep.module.scss';

// Animation variants for step transitions
const stepVariants = {
  enter: (direction: 'forward' | 'backward') => ({
    opacity: 0,
    x: direction === 'forward' ? 20 : -20,
  }),
  center: {
    opacity: 1,
    x: 0,
  },
  exit: (direction: 'forward' | 'backward') => ({
    opacity: 0,
    x: direction === 'forward' ? -20 : 20,
  }),
};

export default function EmailStep({
  email,
  error,
  isPending,
  emailInputRef,
  direction,
  onEmailChange,
  onNext,
}: EmailStepProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <motion.div
      key="email-step"
      custom={direction}
      variants={stepVariants}
      initial={mounted ? "enter" : false}
      animate="center"
      exit="exit"
      transition={{ 
        duration: 0.3,
        ease: [0.16, 1, 0.3, 1] // Smooth Microsoft-style easing
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onNext();
        }}
        noValidate
        aria-label="Sign in with email"
      >
        <InputField
          ref={emailInputRef}
          id="email"
          name="email"
          type="email"
          label="Email"
          value={email}
          onChange={(e) => {
            onEmailChange(e.target.value);
          }}
          error={error || undefined}
          disabled={isPending}
          autoComplete="email"
          required
        />

        <NextButton
          type="submit"
          isLoading={isPending}
          disabled={!email.trim() || isPending}
        >
          Next
        </NextButton>
      </form>

      {/* "or" separator */}
      <div className={styles.separator}>
        <div className={styles.separatorLine}></div>
        <span className={styles.separatorText}>or</span>
        <div className={styles.separatorLine}></div>
      </div>

      {/* Provider buttons */}
      <div className={styles.providerButtons}>
        <GoogleButton
          label="Continue with Google"
          callbackUrl="/"
          className="providerButtonDark"
        />
        <GitHubButton
          label="Continue with GitHub"
          callbackUrl="/"
          className="providerButtonDark"
        />
      </div>
    </motion.div>
  );
}
