'use client';

import { useState } from 'react';
import { useDisclosure, Button, VStack, Heading, HStack, Text } from '@chakra-ui/react';
import AuthModal from '@/components/auth/AuthModal';

export default function HomePage() {
  const { isOpen, onOpen, onClose } = useDisclosure();
  const [initialTab, setInitialTab] = useState<'login' | 'signup'>('login');

  const openLogin = () => {

    setInitialTab('login');
    onOpen();
  };
  const openSignup = () => {

    setInitialTab('signup');
    onOpen();
  };


  return (
    <>
      <VStack minH="70vh" align="center" justify="center" spacing={6}>
        <Heading size="lg" textAlign="center">
          Welcome to M2 Auth & Profiles
        </Heading>

        <HStack spacing={3}>
          <Button size="lg" onClick={openLogin}>Sign in</Button>
          <Button size="lg" colorScheme="blue" onClick={openSignup}>Sign up</Button>
        </HStack>

      </VStack>

      <AuthModal
        isOpen={isOpen}
        onCloseAction={onClose}
        initialTab={initialTab}
      />
    </>
  );
}