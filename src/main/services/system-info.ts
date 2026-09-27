import os from 'node:os';
import { readdir, statfs } from 'node:fs/promises';
import type { NetInterface, SystemSnapshot } from '../../shared/api';
import { getWindowsFacts } from './windows-security';

let prevCpu: { idle: number; total: number } | null = null;

function cpuTimes() {
  let idle = 0;
  let total = 0;
  for (const c of os.cpus()) {
    const t = c.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
  }
  return { idle, total };
}

/** CPU usage since the previous call (null on the first call; the UI polls, so it fills in quickly). */
function sampleCpuUsage(): number | null {
  const now = cpuTimes();
  const prev = prevCpu;
  prevCpu = now;
  if (!prev) return null;
  const dTotal = now.total - prev.total;
  const dIdle = now.idle - prev.idle;
  if (dTotal <= 0) return null;
  return Math.max(0, Math.min(100, Math.round(((dTotal - dIdle) / dTotal) * 1000) / 10));
}

function interfaces(): NetInterface[] {
  const out: NetInterface[] = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs ?? []) {
      out.push({ name, address: a.address, family: a.family === 'IPv4' ? 'IPv4' : 'IPv6', mac: a.mac, internal: a.internal });
    }
  }
  return out;
}

async function linuxProcessCount(): Promise<number | null> {
  try {
    return (await readdir('/proc')).filter((d) => /^\d+$/.test(d)).length;
  } catch {
    return null;
  }
}

export async function getSystemSnapshot(): Promise<SystemSnapshot> {
  const cpus = os.cpus();
  const total = os.totalmem();
  const free = os.freemem();
  const root = process.platform === 'win32' ? `${process.env.SystemDrive || 'C:'}\\` : '/';

  let disk: SystemSnapshot['disk'] = null;
  try {
    const s = await statfs(root);
    const totalBytes = s.blocks * s.bsize;
    const freeBytes = s.bavail * s.bsize;
    disk = { mount: root, totalBytes, freeBytes, usedPercent: totalBytes ? Math.round(((totalBytes - freeBytes) / totalBytes) * 1000) / 10 : 0, mediaType: null };
  } catch {
    disk = null;
  }

  const ifaces = interfaces();
  const external = ifaces.filter((i) => !i.internal && !i.address.startsWith('fe80'));
  const primary = external.find((i) => i.family === 'IPv4') ?? null;

  const win = await getWindowsFacts();
  const release = os.release();

  return {
    platform: process.platform,
    osName: win.osCaption ?? (process.platform === 'win32' ? 'Windows' : `${os.type()} ${release}`),
    osVersion: win.osVersion ?? release,
    osBuild: win.osBuild ?? (process.platform === 'win32' ? release.split('.').pop() ?? null : null),
    arch: os.arch(),
    uptimeSec: Math.round(os.uptime()),
    cpu: {
      model: cpus[0]?.model?.trim() ?? 'Unknown',
      logicalCores: cpus.length,
      physicalCores: win.physicalCores,
      speedMHz: cpus[0]?.speed ?? 0,
      usagePercent: sampleCpuUsage(),
    },
    memory: { totalBytes: total, freeBytes: free, usedPercent: Math.round(((total - free) / total) * 1000) / 10 },
    disk,
    interfaces: ifaces,
    primaryIPv4: primary?.address ?? null,
    networkUp: external.length > 0,
    processCount: win.processCount ?? (process.platform === 'linux' ? await linuxProcessCount() : null),
  };
}
