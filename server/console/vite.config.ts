import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const mockTarget = process.env.WATCHPOST_API_TARGET ?? 'http://127.0.0.1:8787';

export default defineConfig({
  plugins: [react()],
  // Served at the root of the same host as the API: absolute paths.
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // No inline script or style: the server CSP is strict.
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        // The MapLibre worker (.mjs) is published as .js: any file server serves it as text/javascript.
        assetFileNames: (info) =>
          (info.names?.[0] ?? '').endsWith('.mjs') ? 'assets/[name]-[hash].js' : 'assets/[name]-[hash][extname]',
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: mockTarget, changeOrigin: false },
      '/healthz': { target: mockTarget },
    },
  },
  preview: {
    proxy: {
      '/api': { target: mockTarget },
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
