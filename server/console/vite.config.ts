import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const mockTarget = process.env.VIGIE_API_TARGET ?? 'http://127.0.0.1:8787';

export default defineConfig({
  plugins: [react()],
  // Servi à la racine du même hôte que l'API : chemins absolus.
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // Pas de script ni de style en ligne : la CSP serveur est stricte.
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1200,
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
