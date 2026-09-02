import type { Metadata } from 'next';
import './globals.css';
import Footer from './components/Footer';
import DebugPanel from './components/DebugPanel';

export const metadata: Metadata = {
  title: '0account Auth Example',
  description: 'Showcase of signing in with 0account over OpenID Connect.',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col bg-zinc-950 text-zinc-50">
        {children}
        <Footer />
        {/* On every page: a failure during sign-in and a failure during logout
            happen on different ones, and neither is worth missing. */}
        <DebugPanel />
      </body>
    </html>
  );
}
