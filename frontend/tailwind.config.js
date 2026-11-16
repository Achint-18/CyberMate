/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0d12',
          surface: '#111620',
          elevated: '#171e2c',
          border: '#232c3d',
          subtle: '#2d3748',
          text: '#e6edf3',
          muted: '#8b949e',
          accent: '#00c875',
          accentHover: '#00b067',
          accentSubtle: 'rgba(0, 200, 117, 0.12)',
        },
        light: {
          bg: '#f8fafc',
          surface: '#ffffff',
          elevated: '#f1f5f9',
          border: '#e2e8f0',
          subtle: '#cbd5e1',
          text: '#0f172a',
          muted: '#64748b',
          accent: '#059669',
          accentHover: '#047857',
          accentSubtle: 'rgba(5, 150, 105, 0.1)',
        },
        severity: {
          low: '#10b981',      // Emerald
          medium: '#f59e0b',   // Amber
          high: '#f97316',     // Orange
          critical: '#ef4444', // Red
        }
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'Inter',
          'sans-serif'
        ],
        mono: [
          '"JetBrains Mono"',
          '"Fira Code"',
          'Consolas',
          'Monaco',
          'monospace'
        ]
      }
    },
  },
  plugins: [],
}
