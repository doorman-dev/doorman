import type { Metadata } from 'next'
import './globals.css'
import { AuthProvider } from '@/contexts/AuthContext'
import { ToastProvider } from '@/contexts/ToastContext'
import { Toaster } from 'react-hot-toast'

export const metadata: Metadata = {
  title: 'Doorman',
  description: 'Gateway for your APIs and AI providers.',
  icons: { icon: [{ url: '/favicon.svg?v=8', type: 'image/svg+xml' }], apple: [{ url: '/apple-touch-icon.png?v=8', sizes: '180x180', type: 'image/png' }] },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en" className="h-full" suppressHydrationWarning><head><link rel="preconnect" href="https://fonts.googleapis.com" /><link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" /><link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" /></head><body className="h-full"><AuthProvider><ToastProvider>{children}</ToastProvider></AuthProvider><Toaster position="top-center" /></body></html>
}
