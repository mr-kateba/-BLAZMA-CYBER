// Browser extension audit: finds Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera,
// Chromium) and Firefox profiles for the current user and reads — never writes — the files the
// browser keeps about its extensions. Sizes and counts are capped; nothing is executed or uploaded.

import { existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { chromiumSettings, parseChromiumExtension, parseFirefoxExtensions, sortExtensions, type BrowserExtension, type BrowserId, type ExtensionAudit } from '../../core/extensions';

export interface BrowserRoot {
  browser: BrowserId;
  /** Chromium "User Data" folder (profiles inside) or a single profile folder; Firefox "Profiles" folder. */
  dir: string;
}

const MAX_EXT = 1000;

export function defaultBrowserRoots(): BrowserRoot[] {
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local');
    const roaming = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming');
    return [
      { browser: 'chrome', dir: join(local, 'Google', 'Chrome', 'User Data') },
      { browser: 'edge', dir: join(local, 'Microsoft', 'Edge', 'User Data') },
      { browser: 'brave', dir: join(local, 'BraveSoftware', 'Brave-Browser', 'User Data') },
      { browser: 'vivaldi', dir: join(local, 'Vivaldi', 'User Data') },
      { browser: 'chromium', dir: join(local, 'Chromium', 'User Data') },
      { browser: 'opera', dir: join(roaming, 'Opera Software', 'Opera Stable') },
      { browser: 'firefox', dir: join(roaming, 'Mozilla', 'Firefox', 'Profiles') },
    ];
  }
  const cfg = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config');
  return [
    { browser: 'chrome', dir: join(cfg, 'google-chrome') },
    { browser: 'edge', dir: join(cfg, 'microsoft-edge') },
    { browser: 'brave', dir: join(cfg, 'BraveSoftware', 'Brave-Browser') },
    { browser: 'vivaldi', dir: join(cfg, 'vivaldi') },
    { browser: 'chromium', dir: join(cfg, 'chromium') },
    { browser: 'opera', dir: join(cfg, 'opera') },
    { browser: 'firefox', dir: join(homedir(), '.mozilla', 'firefox') },
  ];
}

async function readCapped(path: string, max: number): Promise<string | null> {
  try {
    const st = await stat(path);
    if (!st.isFile() || st.size > max) return null;
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

const dirs = async (p: string) => (await readdir(p, { withFileTypes: true }).catch(() => [])).filter((d) => d.isDirectory()).map((d) => d.name);

async function chromiumProfile(browser: BrowserId, profileDir: string, profile: string, out: BrowserExtension[]): Promise<void> {
  const extDir = join(profileDir, 'Extensions');
  if (!existsSync(extDir)) return;
  const settings = chromiumSettings(
    await readCapped(join(profileDir, 'Secure Preferences'), 32 * 1024 * 1024),
    await readCapped(join(profileDir, 'Preferences'), 32 * 1024 * 1024),
  );
  for (const id of await dirs(extDir)) {
    if (out.length >= MAX_EXT) return;
    if (!/^[a-p]{32}$/.test(id)) continue;
    // Several versions can be present during an update; the newest folder is the active one.
    const versions = (await dirs(join(extDir, id))).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
    const vdir = versions[0] ? join(extDir, id, versions[0]) : null;
    if (!vdir) continue;
    const manifest = await readCapped(join(vdir, 'manifest.json'), 1024 * 1024);
    if (!manifest) continue;
    let messages: unknown = null;
    if (manifest.includes('__MSG_')) {
      let loc = 'en';
      try {
        loc = String((JSON.parse(manifest.replace(/^﻿/, '')) as { default_locale?: string }).default_locale ?? 'en');
      } catch { /* keep en */ }
      for (const l of [loc, loc.replace('-', '_'), 'en', 'en_US']) {
        if (!/^[A-Za-z_-]{2,10}$/.test(l)) continue;
        const text = await readCapped(join(vdir, '_locales', l, 'messages.json'), 1024 * 1024);
        if (text) {
          try {
            messages = JSON.parse(text.replace(/^﻿/, ''));
            break;
          } catch { /* try next */ }
        }
      }
    }
    const ext = parseChromiumExtension(browser, profile, id, manifest, messages, settings[id]);
    if (ext) out.push(ext);
  }
}

export async function auditExtensions(roots: BrowserRoot[] = defaultBrowserRoots(), now: Date = new Date()): Promise<ExtensionAudit> {
  const out: BrowserExtension[] = [];
  const browsers: ExtensionAudit['browsers'] = [];
  for (const { browser, dir } of roots) {
    if (!existsSync(dir)) continue;
    let profiles = 0;
    if (browser === 'firefox') {
      for (const p of await dirs(dir)) {
        const text = await readCapped(join(dir, p, 'extensions.json'), 32 * 1024 * 1024);
        if (text === null) continue;
        profiles++;
        out.push(...parseFirefoxExtensions(p, text).slice(0, MAX_EXT - out.length));
      }
    } else if (existsSync(join(dir, 'Extensions'))) {
      profiles = 1; // Opera keeps a single profile in its root folder
      await chromiumProfile(browser, dir, 'Default', out);
    } else {
      for (const p of await dirs(dir)) {
        if (p !== 'Default' && !/^Profile \d+$/.test(p)) continue;
        profiles++;
        await chromiumProfile(browser, join(dir, p), p, out);
      }
    }
    if (profiles > 0) browsers.push({ browser, profiles });
  }
  return { extensions: sortExtensions(out), browsers, collectedAt: now.toISOString() };
}
