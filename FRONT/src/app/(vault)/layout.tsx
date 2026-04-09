import { VaultShell } from '@/components/Layout';

export default function VaultLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return <VaultShell>{children}</VaultShell>;
}
