import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

// Renderer build only. Main + preload are bundled by scripts/build-main.mjs (esbuild).
export default defineConfig({
  root: resolve(__dirname, 'src/renderer'),
  base: './',
  plugins: [react()],
  resolve: { alias: { '@locales': resolve(__dirname, 'locales') } },
  build: {
    outDir: resolve(__dirname, 'dist/renderer'),
    emptyOutDir: true,
    target: 'chrome130',
  },
  server: { port: 5178, strictPort: true },
});
