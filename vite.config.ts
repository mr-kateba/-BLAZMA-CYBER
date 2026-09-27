import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

// Renderer build only. Main + preload are bundled by scripts/build-main.mjs (esbuild).
export default defineConfig(({ command }) => ({
  root: resolve(__dirname, 'src/renderer'),
  base: './',
  plugins: [
    react(),
    {
      // The dev server's HMR websocket is allowed by CSP only in `vite serve`, never in builds.
      name: 'blazma-csp',
      transformIndexHtml: (html: string) => html.replace('%DEV_CONNECT%', command === 'serve' ? ' ws://localhost:5178' : ''),
    },
  ],
  resolve: { alias: { '@locales': resolve(__dirname, 'locales') } },
  build: {
    outDir: resolve(__dirname, 'dist/renderer'),
    emptyOutDir: true,
    target: 'chrome130',
  },
  server: { port: 5178, strictPort: true },
}));
