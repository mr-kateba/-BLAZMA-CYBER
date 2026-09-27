// Window chrome (background + Windows caption buttons) that matches the selected theme.
import { nativeTheme, type BrowserWindow } from 'electron';
import type { Theme } from '../shared/api';

const CHROME = {
  dark: { background: '#060b18', overlay: { color: '#070d1c', symbolColor: '#8fa6cf' } },
  midnight: { background: '#020409', overlay: { color: '#04060c', symbolColor: '#8fa6cf' } },
  light: { background: '#f3f6fb', overlay: { color: '#fbfcfe', symbolColor: '#3d4d6b' } },
} as const;

let current: Theme = 'dark';

function resolved(theme: Theme): keyof typeof CHROME {
  if (theme === 'system') return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
  return theme;
}

/** Colours for a new window, and the source the renderer's prefers-color-scheme follows. */
export function windowChrome(theme: Theme) {
  current = theme;
  nativeTheme.themeSource = theme === 'system' ? 'system' : theme === 'light' ? 'light' : 'dark';
  return CHROME[resolved(theme)];
}

export function applyWindowTheme(win: BrowserWindow | null, theme: Theme = current): void {
  const c = windowChrome(theme);
  if (!win || win.isDestroyed()) return;
  win.setBackgroundColor(c.background);
  try {
    win.setTitleBarOverlay({ ...c.overlay, height: 60 });
  } catch {
    /* no caption-button overlay on this platform */
  }
}

/** In 'system' mode the caption buttons follow Windows switching between light and dark. */
export function followSystemTheme(getWin: () => BrowserWindow | null): void {
  nativeTheme.on('updated', () => {
    if (current === 'system') applyWindowTheme(getWin());
  });
}
