import type { ReactNode } from 'react';
import type { BoxProps } from '@chakra-ui/react';

export type RegistrationLayoutProps = {
  onSuccess?: () => void;

  /** Visual toggles / slots */
  showImage?: boolean;
  imageSlot?: ReactNode;
  signupSlot?: ReactNode;

  /** Chakra passthrough props for layout areas */
  containerProps?: BoxProps;
  imageProps?: BoxProps;
  contentProps?: BoxProps;
};
