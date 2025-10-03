
import type { ReactNode } from 'react';
import '@/styles/globals.scss';
import Providers from './providers';
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
