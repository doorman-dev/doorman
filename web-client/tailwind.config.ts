import type { Config } from "tailwindcss";

export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      // doorman.dev design system (dark). The markup was written for a light
      // theme, so each scale runs from the darkest tint (50) to the brightest
      // text (950): light-theme classes render as the site's dark UI.
      colors: {
        white: '#111114',
        black: '#000000',
        signal: { ink: '#f4f4f5', warm: '#0e0e11', lime: '#13203a', blue: '#0f1626', terra: '#6b9bff', mist: '#a1a1aa' },
        gray: { 50: '#0e0e11', 100: '#17171b', 200: '#232327', 300: '#303036', 400: '#6e6e78', 500: '#8b8b95', 600: '#a1a1aa', 700: '#d4d4d8', 800: '#e4e4e7', 900: '#f4f4f5', 950: '#fafafa' },
        slate: { 50: '#0e0e11', 100: '#17171b', 200: '#232327', 300: '#303036', 400: '#6e6e78', 500: '#8b8b95', 600: '#a1a1aa', 700: '#d4d4d8', 800: '#e4e4e7', 900: '#f4f4f5', 950: '#fafafa' },
        zinc: { 50: '#0e0e11', 100: '#17171b', 200: '#232327', 300: '#303036', 400: '#6e6e78', 500: '#8b8b95', 600: '#a1a1aa', 700: '#d4d4d8', 800: '#e4e4e7', 900: '#f4f4f5', 950: '#fafafa' },
        neutral: { 50: '#0e0e11', 100: '#17171b', 200: '#232327', 300: '#303036', 400: '#6e6e78', 500: '#8b8b95', 600: '#a1a1aa', 700: '#d4d4d8', 800: '#e4e4e7', 900: '#f4f4f5', 950: '#fafafa' },
        primary: { 50: '#0f1626', 100: '#13203a', 200: '#1b2f57', 300: '#2a4a8a', 400: '#4a7ae0', 500: '#2f6bf2', 600: '#6b9bff', 700: '#8fb3ff', 800: '#b3cbff', 900: '#d6e3ff', 950: '#ebf1ff' },
        blue: { 50: '#0f1626', 100: '#13203a', 200: '#1b2f57', 300: '#2a4a8a', 400: '#4a7ae0', 500: '#2f6bf2', 600: '#6b9bff', 700: '#8fb3ff', 800: '#b3cbff', 900: '#d6e3ff', 950: '#ebf1ff' },
        sky: { 50: '#0f1626', 100: '#13203a', 200: '#1b2f57', 300: '#2a4a8a', 400: '#4a7ae0', 500: '#2f6bf2', 600: '#6b9bff', 700: '#8fb3ff', 800: '#b3cbff', 900: '#d6e3ff', 950: '#ebf1ff' },
        indigo: { 50: '#0f1626', 100: '#13203a', 200: '#1b2f57', 300: '#2a4a8a', 400: '#4a7ae0', 500: '#2f6bf2', 600: '#6b9bff', 700: '#8fb3ff', 800: '#b3cbff', 900: '#d6e3ff', 950: '#ebf1ff' },
        success: { 50: '#0c1a12', 100: '#10241a', 200: '#17402a', 300: '#1f6b40', 400: '#22c55e', 500: '#4ade80', 600: '#4ade80', 700: '#86efac', 800: '#bbf7d0', 900: '#dcfce7', 950: '#f0fdf4' },
        green: { 50: '#0c1a12', 100: '#10241a', 200: '#17402a', 300: '#1f6b40', 400: '#22c55e', 500: '#4ade80', 600: '#4ade80', 700: '#86efac', 800: '#bbf7d0', 900: '#dcfce7', 950: '#f0fdf4' },
        emerald: { 50: '#0c1a12', 100: '#10241a', 200: '#17402a', 300: '#1f6b40', 400: '#22c55e', 500: '#4ade80', 600: '#4ade80', 700: '#86efac', 800: '#bbf7d0', 900: '#dcfce7', 950: '#f0fdf4' },
        warning: { 50: '#1f1806', 100: '#2a200a', 200: '#4a370f', 300: '#7c5a14', 400: '#f59e0b', 500: '#fbbf24', 600: '#fbbf24', 700: '#fcd34d', 800: '#fde68a', 900: '#fef3c7', 950: '#fffbeb' },
        amber: { 50: '#1f1806', 100: '#2a200a', 200: '#4a370f', 300: '#7c5a14', 400: '#f59e0b', 500: '#fbbf24', 600: '#fbbf24', 700: '#fcd34d', 800: '#fde68a', 900: '#fef3c7', 950: '#fffbeb' },
        yellow: { 50: '#1f1806', 100: '#2a200a', 200: '#4a370f', 300: '#7c5a14', 400: '#f59e0b', 500: '#fbbf24', 600: '#fbbf24', 700: '#fcd34d', 800: '#fde68a', 900: '#fef3c7', 950: '#fffbeb' },
        orange: { 50: '#1f1806', 100: '#2a200a', 200: '#4a370f', 300: '#7c5a14', 400: '#f59e0b', 500: '#fbbf24', 600: '#fbbf24', 700: '#fcd34d', 800: '#fde68a', 900: '#fef3c7', 950: '#fffbeb' },
        error: { 50: '#1f0f10', 100: '#2a1314', 200: '#4a1d1f', 300: '#7f2b2d', 400: '#ef4444', 500: '#f87171', 600: '#f87171', 700: '#fca5a5', 800: '#fecaca', 900: '#fee2e2', 950: '#fff1f1' },
        red: { 50: '#1f0f10', 100: '#2a1314', 200: '#4a1d1f', 300: '#7f2b2d', 400: '#ef4444', 500: '#f87171', 600: '#f87171', 700: '#fca5a5', 800: '#fecaca', 900: '#fee2e2', 950: '#fff1f1' },
        rose: { 50: '#1f0f10', 100: '#2a1314', 200: '#4a1d1f', 300: '#7f2b2d', 400: '#ef4444', 500: '#f87171', 600: '#f87171', 700: '#fca5a5', 800: '#fecaca', 900: '#fee2e2', 950: '#fff1f1' },
        purple: { 50: '#18122a', 100: '#21183a', 200: '#352560', 300: '#5b3fa3', 400: '#8b5cf6', 500: '#a78bfa', 600: '#a78bfa', 700: '#c4b5fd', 800: '#ddd6fe', 900: '#ede9fe', 950: '#f5f3ff' },
        violet: { 50: '#18122a', 100: '#21183a', 200: '#352560', 300: '#5b3fa3', 400: '#8b5cf6', 500: '#a78bfa', 600: '#a78bfa', 700: '#c4b5fd', 800: '#ddd6fe', 900: '#ede9fe', 950: '#f5f3ff' },
        dark: { bg: '#09090b', surface: '#111114', surfaceHover: '#17171b', border: '#232327', text: '#f4f4f5', textSecondary: '#a1a1aa' },
      },
      fontFamily: {
        sans: ['"Instrument Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideDown: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        scaleIn: {
          '0%': { transform: 'scale(0.95)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
      },
      borderRadius: {
        'xs': '4px', 'sm': '6px', 'md': '8px', 'lg': '10px', 'xl': '12px', '2xl': '16px',
      },
      boxShadow: {
        'soft': '0 1px 2px rgba(0, 0, 0, 0.3)', 'medium': '0 10px 30px -12px rgba(0, 0, 0, 0.6)', 'strong': '0 30px 80px -20px rgba(0, 0, 0, 0.8)',
        'xl': '0 30px 80px -20px rgba(0, 0, 0, 0.8)',
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
} satisfies Config;
