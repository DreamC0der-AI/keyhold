import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@keyhold': fileURLToPath(new URL('../../src', import.meta.url)) } },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 2000 },
  esbuild: { target: 'es2022' },
  optimizeDeps: { esbuildOptions: { target: 'es2022' } },
  server: { fs: { allow: ['../..'] } },
});
