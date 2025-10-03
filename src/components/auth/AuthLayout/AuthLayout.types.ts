import type { ReactNode } from 'react';
import type { BoxProps } from '@chakra-ui/react';

export type AuthLayoutProps = {
  onSuccessAction?: () => void;
  initialTab?: 'login' | 'signup';

  /** Visual toggles / slots */
  showImage?: boolean;
  imageSlot?: ReactNode;
  signupSlot?: ReactNode;

  /** Chakra passthrough props for layout areas */
  containerProps?: BoxProps;
  imageProps?: BoxProps;
  contentProps?: BoxProps;
  // NOTE: initialTab is accepted; if/when you add tabs, wire it here.
  // onSuccessAction can be passed to forms if you want to call a function after successful signup/signin.
};
