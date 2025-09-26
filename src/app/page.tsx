'use client';

import { useDisclosure, Button, VStack, Heading } from '@chakra-ui/react';
import RegistrationModal from '@/components/registration/RegistrationModal/RegistrationModal';

export default function HomePage() {
  const { isOpen, onOpen, onClose } = useDisclosure();

  return (
    <>
      <VStack minH="70vh" align="center" justify="center" spacing={6}>
        <Heading size="lg" textAlign="center">
          Welcome to M2 Auth & Profiles
        </Heading>
        <VStack spacing={3}>

          <Button size="lg" colorScheme="blue" onClick={onOpen}>
            Sign up
          </Button>
        </VStack>
      </VStack>

      <RegistrationModal
        isOpen={isOpen}
        onClose={onClose}
     
      />
    </>
  );
}
