// Development mode: Vite dev server (hot reload for the UI) + Electron main process.
import { createServer } from 'vite';
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

execFileSync(process.execPath, ['scripts/build-main.mjs'], { stdio: 'inherit' });
const server = await createServer({ configFile: 'vite.config.ts' });
await server.listen();
const url = server.resolvedUrls.local[0];
const electronPath = createRequire(import.meta.url)('electron');

const child = spawn(electronPath, ['.'], {
  stdio: 'inherit',
  env: { ...process.env, BLAZMA_DEV_URL: url, BLAZMA_DEV: '1' },
});
child.on('exit', async (code) => {
  await server.close();
  process.exit(code ?? 0);
});
