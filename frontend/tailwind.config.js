/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          bg: "#0a0e17",
          panel: "#111827",
          card: "#1a2332",
          hover: "#1f2b3d",
          border: "#2a3a4e",
        },
        sev: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#3b82f6",
          info: "#6b7280",
        },
        accent: {
          primary: "#06b6d4",
          success: "#10b981",
          warning: "#f59e0b",
          danger: "#ef4444",
        },
        text: {
          primary: "#f1f5f9",
          secondary: "#94a3b8",
          muted: "#64748b",
        },
      },
      fontFamily: {
        sans: ['"Segoe UI"', "Tahoma", "Arial", "sans-serif"],
        mono: ['"Cascadia Code"', '"Fira Code"', "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
