/** Colours are driven by the CSS custom properties in style.css (the theme toggle flips them). */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)', panel: 'var(--panel)', panel2: 'var(--panel2)',
        line: 'var(--line)', line2: 'var(--line2)',
        txt: 'var(--txt)', dim: 'var(--dim)', muted: 'var(--muted)',
        accent: 'var(--accent)', ok: 'var(--ok)', warn: 'var(--warn)', bad: 'var(--bad)'
      },
      maxWidth: { content: '1080px' }
    }
  },
  plugins: []
}
