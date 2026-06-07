import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// SPA is mounted by the Go binary at /portal and /admin via internal/httpx/spa.
// During development we run Vite on :5173 and proxy API calls back to the Go
// server on :8080. The dev server uses HTML5 history fallback so deep links
// (/portal/sessions etc.) survive a refresh.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/portal/api': 'http://localhost:8080',
      '/admin/api':  'http://localhost:8080',
      '/oauth':      'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    target: 'es2022',
  },
})
