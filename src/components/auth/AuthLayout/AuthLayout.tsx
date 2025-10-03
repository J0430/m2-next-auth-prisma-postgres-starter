'use client';
import { ReactNode } from 'react';
import { Box, Flex } from '@chakra-ui/react';
import styles from './AuthLayout.module.scss';
import type { AuthLayoutProps } from './AuthLayout.types';
import LoginImage from '../shared/LoginImage';
import SignInForm from '../SignInForm/SignInForm';
import SignupForm from '@/components/registration/SignupForm';
 // NOTE: SignupForm currently lives under components/registration (by design).
export default function AuthLayout({
  onSuccessAction,
  initialTab,
  showImage = true,
  imageSlot,
  signupSlot,
  containerProps,
  imageProps,
  contentProps,
}: AuthLayoutProps) {
  const ImageArea: ReactNode = imageSlot ?? <LoginImage />;
  const defaultForm = initialTab === 'signup'
    ? (<SignupForm onSuccess={onSuccessAction} />)
    : (<SignInForm />);
  const SignupArea: ReactNode = signupSlot ?? defaultForm;
  // NOTE: initialTab accepted for future tabbed UI
  // NOTE: onSuccessAction can be passed to forms later
  return (
    <Flex
      className={styles.container}
      {...containerProps}
      direction={{ base: 'column', md: 'row' }}
      gap={0}
    >
      {showImage && (
        <Box
          className={styles.image}
          display={{ base: 'none', md: 'block' }}
          w={{ md: '45%' }}
          {...imageProps}
        >
          {ImageArea}
        </Box>
      )}
      <Box
        className={styles.content}
        w={{ base: '100%', md: showImage ? '55%' : '100%' }}
        p={{ base: 6, md: 8 }}
        {...contentProps}
      >
        {SignupArea}
      </Box>
    </Flex>
  );
}