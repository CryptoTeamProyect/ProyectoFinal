import type { Metadata } from 'next';
import { ThemeProvider } from '@/context/ThemeContext';
import '@/styles/index.css';

export const metadata: Metadata = {
  title: 'Secure Digital Vault',
  description: 'Bóveda digital criptográfica',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning>
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
