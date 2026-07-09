/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        void: "#0A0E14",       // page background
        panel: "#0F1620",      // card/panel background
        panelraised: "#141D2B",
        hairline: "#1E2A3D",
        trusted: "#22D3A6",
        suspicious: "#F5A623",
        quarantined: "#FB7C3C",
        blocked: "#EF4444",
        textprimary: "#E2E8F0",
        textdim: "#5B6B82",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
      },
      boxShadow: {
        glow: "0 0 20px rgba(34, 211, 166, 0.15)",
      },
    },
  },
  plugins: [],
};
