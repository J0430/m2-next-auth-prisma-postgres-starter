import type { RefObject } from 'react';

export interface EmailStepProps {
  email: string;
  error: string | null;
  isPending: boolean;
  emailInputRef: RefObject<HTMLInputElement | null>;
  direction: 'forward' | 'backward';
  onEmailChange: (value: string) => void;
  onNext: () => void;
}
