'use client';

import { useRef, useState, useTransition } from 'react';
import type { FormEvent } from 'react';
import {
  Box, Button, VStack, Input, FormControl, FormLabel, Text, useToast,
} from '@chakra-ui/react';
import { signinAction } from '@/lib/auth/signin';

export default function SignInForm() {
  const toast = useToast();
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const formRef = useRef<HTMLFormElement>(null);

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (isPending) return;
    setError(null);

    const form = e.currentTarget;
    const emailEl = form.elements.namedItem('email') as HTMLInputElement | null;
    if (emailEl) emailEl.value = emailEl.value.trim().toLowerCase();

    const fd = new FormData(form);

    startTransition(async () => {
      const res = await signinAction(fd);
      if (!res.ok) {
        setError(res.errors?.formErrors?.[0] ?? 'Sign-in failed');
        return;
      }
      toast.closeAll();
      toast({
        title: 'Signed in',
        description: 'Welcome back!',
        status: 'success',
        position: 'top',
      });
      formRef.current?.reset();
      // Optionally: redirect/refresh here
    });
  }

  return (
    <Box as="form" ref={formRef} onSubmit={onSubmit} noValidate>
      <VStack spacing={4} align="stretch" opacity={isPending ? 0.8 : 1}>
        <FormControl isRequired>
          <FormLabel>Email</FormLabel>
          <Input
            name="email"
            type="email"
            autoComplete="email"
            isRequired
            isDisabled={isPending}
          />
        </FormControl>

        <FormControl isRequired>
          <FormLabel>Password</FormLabel>
          <Input
            name="password"
            type="password"
            autoComplete="current-password"
            minLength={8}
            isRequired
            isDisabled={isPending}
          />
        </FormControl>

        {error && (
          <Text color="red.500" fontSize="sm" aria-live="polite">
            {error}
          </Text>
        )}

        <Button
          type="submit"
          isLoading={isPending}
          colorScheme="blue"
          w="full"
          loadingText="Signing in"
        >
          Sign in
        </Button>
      </VStack>
    </Box>
  );
}