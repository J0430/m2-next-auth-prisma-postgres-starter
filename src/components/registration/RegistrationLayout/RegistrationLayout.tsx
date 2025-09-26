'use client';
import { ReactNode } from 'react';
import { Box, Flex } from '@chakra-ui/react';
import styles from './RegistrationLayout.module.scss';
import type { RegistrationLayoutProps } from './RegistrationLayout.types';
import LoginImage from '../../registration/LoginImage';
import SignupForm from '../SignupForm';

export default function RegistrationLayout({
  onSuccess,
  showImage = true,
  imageSlot,
  signupSlot,
  containerProps,
  imageProps,
  contentProps,
}: RegistrationLayoutProps) {
  const ImageArea: ReactNode = imageSlot ?? <LoginImage />;
  const SignupArea: ReactNode = signupSlot ?? (
    <SignupForm onSuccess={onSuccess} />
  );

  return (
    <Flex className={styles.container} {...containerProps}>
      {showImage && (
        <Box className={styles.image} {...imageProps}>
          {ImageArea}
        </Box>
      )}

      <Box className={styles.content} {...contentProps}>
        <Box className={styles.signupContainer}>{SignupArea}</Box>
      </Box>
    </Flex>
  );
}
