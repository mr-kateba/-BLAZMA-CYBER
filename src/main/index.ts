import { app, BrowserWindow, Menu, session, type IpcMainInvokeEvent } from 'electron';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { registerIpc } from './ipc';
import { logger } from './services/logger';
import { portableDataDir } from './services/paths';

const DEV_URL = process.env.BLAZMA_DEV_URL; // set only by scripts/dev.mjs
const RENDERER_INDEX = join(__dirname, '..', 'renderer', 'index.html');
const RENDERER_BASE = pathToFileURL(join(__dirname, '..', 'renderer')).href;

let win: BrowserWindow | null = null;

function isTrustedUrl(url: string | undefined): boolean {
  if (!url) return false;
  if (DEV_URL && url.startsWith(DEV_URL)) return true;
  return url.startsWith(RENDERER_BASE);
}

function isTrustedSender(e: IpcMainInvokeEvent): boolean {
  return e.senderFrame !== null && e.sender === win?.webContents && isTrustedUrl(e.senderFrame.url);
}

// Portable mode: Chromium's own data (cache, local storage) also stays next to the program, and each
// portable copy gets its own single-instance lock. Must run before anything uses userData.
const portableDir = portableDataDir();
if (portableDir && !process.env.BLAZMA_DATA_DIR) app.setPath('userData', join(portableDir, 'electron'));

// Single instance: a second launch focuses the existing window and exits immediately.
if (!app.requestSingleInstanceLock()) {
  app.exit(0);
}

app.on('second-instance', () => {
  if (win) {
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});

// Hardening that applies to every webContents, including any unexpected one.
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (ev, url) => {
    if (!isTrustedUrl(url)) {
      ev.preventDefault();
      logger.security('navigation_blocked', { url });
    }
  });
  contents.setWindowOpenHandler(({ url }) => {
    // No new windows, ever. External pages open only via the app:openLink IPC, which validates the
    // host, honours Offline Mode and records the request in Network Activity.
    let host = '';
    try {
      host = new URL(url).host;
    } catch {
      /* unparsable */
    }
    logger.security('window_open_blocked', { host });
    return { action: 'deny' };
  });
  contents.on('will-attach-webview', (ev) => ev.preventDefault());
});

function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#060b18',
    title: 'Blazma Cyber',
    show: false,
    titleBarStyle: 'hidden',
    // Same height as the top bar (--topbar-h) so the caption buttons line up with it.
    titleBarOverlay: { color: '#070d1c', symbolColor: '#8fa6cf', height: 60 },
    webPreferences: {
      preload: join(__dirname, '..', 'preload', 'index.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: !app.isPackaged,
    },
  });
  win.once('ready-to-show', () => win?.show());
  win.on('closed', () => (win = null));
  if (DEV_URL) void win.loadURL(DEV_URL);
  else void win.loadFile(RENDERER_INDEX);
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  // Deny every permission request (camera, mic, geolocation, notifications via web API, ...).
  session.defaultSession.setPermissionRequestHandler((_wc, permission, cb) => {
    logger.security('permission_denied', { permission });
    cb(false);
  });
  session.defaultSession.setPermissionCheckHandler(() => false);

  registerIpc(() => win, isTrustedSender);
  logger.info('app_started', { version: app.getVersion(), platform: process.platform });
  createWindow();
});

app.on('window-all-closed', () => app.quit());
