'use client';

import type { ReactNode } from 'react';
import { ChakraProvider } from '@chakra-ui/react';

export default function Providers({ children }: { children: ReactNode }) {
  return <ChakraProvider>{children}</ChakraProvider>;
}


