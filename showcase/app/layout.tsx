import type { Metadata } from 'next';
import './globals.css';
import Footer from './components/Footer';

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
      </body>
    </html>
  );
}
