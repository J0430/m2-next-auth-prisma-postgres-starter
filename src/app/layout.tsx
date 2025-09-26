// app/layout.tsx
'use client';

import { ReactNode } from 'react';
import { ChakraProvider } from '@chakra-ui/react';
import '@/styles/globals.scss';

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <ChakraProvider>
          {children}
        </ChakraProvider>
      </body>
    </html>
  );
}
