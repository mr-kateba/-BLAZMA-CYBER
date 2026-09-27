import { useEffect, useRef, useState } from 'react';
import {
  Activity, ChevronRight, Cpu, Earth, FileSearch, FolderPlus, Globe, HardDrive, Hash, KeyRound, Link2, MemoryStick,
  Monitor, MonitorCog, Network, RefreshCw, Router, ScanSearch, ShieldCheck, Wifi, type LucideIcon,
} from 'lucide-react';
import type { ActivityEntry, SecurityStatus, SystemSnapshot } from '../../shared/api';
import { Card, Dot, EmptyState, ErrorState, Gauge, IconTile, Ltr, Progress, Skeleton, Sparkline, usePoll, Badge, type Tone } from '../components/ui';
import { Constellation } from '../components/Logo';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime, formatDuration } from '../format';
import type { PageId } from '../nav';

const HISTORY = 30;

function StatCard({ icon, tone, label, value, meta, bar, loading }: {
  icon: LucideIcon; tone: Tone; label: string; value?: string | null; meta?: React.ReactNode; bar?: number; loading: boolean;
}) {
  return (
    <div className="card stat">
      <IconTile icon={icon} tone={tone} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="stat-label">{label}</div>
        {loading ? (
          <div className="col" style={{ gap: 7, marginTop: 5 }}>
            <Skeleton w="70%" h={16} />
            <Skeleton w="50%" h={11} />
          </div>
        ) : (
          <>
            <div className={`stat-value ${value && value.length > 22 ? 'long' : ''}`} title={value ?? undefined}>{value}</div>
            {bar !== undefined && <div style={{ margin: '7px 0 5px' }}><Progress value={bar} /></div>}
            <div className="stat-meta">{meta}</div>
          </>
        )}
      </div>
    </div>
  );
}

function SecurityList({ sec, snap, qCount }: { sec: SecurityStatus | null; snap: SystemSnapshot | null; qCount: number | null }) {
  const { t, locale } = useI18n();
  const { settings } = useApp();
  if (!sec || !snap) {
    return (
      <div className="status-list">
        {[0, 1, 2, 3].map((i) => <Skeleton key={i} h={14} w={`${80 - i * 8}%`} />)}
      </div>
    );
  }
  const items: Array<{ tone: Tone; text: string; sub?: string }> = [];
  items.push(snap.networkUp ? { tone: 'green', text: t('status.networkUp') } : { tone: 'amber', text: t('status.networkDown') });

  const d = sec.defender;
  if (!sec.platformSupported) {
    items.push({ tone: 'gray', text: t('status.windowsOnly') });
  } else if (!d.available) {
    items.push({ tone: 'amber', text: t('status.defenderUnavailable'), sub: d.reason ? t(`errors.${d.reason}`) : undefined });
  } else if (d.antivirusEnabled === 'off') {
    items.push({ tone: 'red', text: t('status.defenderAvOff') });
  } else if (d.realTimeProtection === 'off') {
    items.push({ tone: 'red', text: t('status.defenderRtpOff') });
  } else {
    items.push({
      tone: 'green',
      text: t('status.defenderOn'),
      sub: d.signatureVersion ? t('status.signatures', { version: d.signatureVersion, age: d.signatureAgeDays ?? '?' }) : undefined,
    });
  }

  if (sec.platformSupported) {
    const f = sec.firewall;
    if (!f.available || !f.profiles) items.push({ tone: 'amber', text: t('status.firewallUnavailable') });
    else {
      const on = f.profiles.filter((p) => p.enabled).length;
      const total = f.profiles.length;
      items.push(
        on === total ? { tone: 'green', text: t('status.firewallOn', { on, total }) }
          : on === 0 ? { tone: 'red', text: t('status.firewallOff') }
          : { tone: 'amber', text: t('status.firewallPartial', { on, total }) },
      );
    }
    if (d.available) items.push({ tone: 'blue', text: t('status.lastQuickScan', { time: d.lastQuickScan ? formatDateTime(locale, d.lastQuickScan) : t('status.never') }) });
  }
  if (qCount !== null) items.push({ tone: qCount > 0 ? 'amber' : 'green', text: t('dashboard.quarantineCount', { count: qCount }) });
  items.push(settings.offlineMode ? { tone: 'cyan', text: t('status.offlineOn') } : { tone: 'green', text: t('status.offlineOff') });

  return (
    <div className="status-list">
      {items.map((it, i) => (
        <div key={i} className="status-item">
          <Dot tone={it.tone} />
          <div>
            <div style={{ color: 'var(--text)' }}>{it.text}</div>
            {it.sub && <div className="tiny dim">{it.sub}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function PublicIp() {
  const { t } = useI18n();
  const { settings, toast } = useApp();
  const [state, setState] = useState<{ ip?: string; loading?: boolean; error?: string }>({});
  const check = async () => {
    setState({ loading: true });
    const r = await window.blazma.privacy.publicIp();
    if (r.ok) setState({ ip: r.data.ip });
    else {
      setState({ error: r.error });
      if (r.error !== 'offline_mode') toast('red', t(`errors.${r.error}`));
    }
  };
  return (
    <div className="row" style={{ gap: 14, alignItems: 'flex-start' }}>
      <IconTile icon={Globe} tone="blue" />
      <div style={{ minWidth: 0 }}>
        <div className="row stat-label">
          {t('dashboard.publicIp')} <Badge tone="amber">{t('common.external')}</Badge>
        </div>
        {state.ip ? (
          <div className="stat-value"><Ltr mono>{state.ip}</Ltr></div>
        ) : state.loading ? (
          <Skeleton w={130} h={18} style={{ marginTop: 5 }} />
        ) : state.error === 'offline_mode' || settings.offlineMode ? (
          <div className="stat-meta" style={{ marginTop: 4, color: 'var(--cyan)' }}>{t('dashboard.publicIpBlocked')}</div>
        ) : (
          <div className="stat-meta" style={{ marginTop: 4 }}>{t('dashboard.publicIpHidden')}</div>
        )}
        {!settings.offlineMode && !state.ip && (
          <button className="btn sm" style={{ marginTop: 8 }} onClick={check} disabled={state.loading}>
            {t('dashboard.publicIpCheck')}
          </button>
        )}
        <div className="tiny dim" style={{ marginTop: 6, maxWidth: 240 }}>{t('dashboard.publicIpNote')}</div>
      </div>
    </div>
  );
}

interface Tool { id: string; icon: LucideIcon; tone: Tone; to: PageId; phase?: number }
const TOOLS: Tool[] = [
  { id: 'quickScan', icon: ShieldCheck, tone: 'green', to: 'security-center' },
  { id: 'scanFile', icon: FileSearch, tone: 'purple', to: 'file-analyzer' },
  { id: 'yara', icon: ScanSearch, tone: 'purple', to: 'yara' },
  { id: 'hashLab', icon: Hash, tone: 'purple', to: 'hash-lab' },
  { id: 'ipLookup', icon: Earth, tone: 'blue', to: 'ip-intel' },
  { id: 'domainLookup', icon: Link2, tone: 'blue', to: 'domain-intel' },
  { id: 'passwordRecovery', icon: KeyRound, tone: 'amber', to: 'password-recovery' },
  { id: 'networkTools', icon: Network, tone: 'green', to: 'network-toolkit' },
  { id: 'privacy', icon: ShieldCheck, tone: 'cyan', to: 'privacy' },
  { id: 'newCase', icon: FolderPlus, tone: 'purple', to: 'cases' },
];

const ACTIVITY_ICON: Record<ActivityEntry['kind'], LucideIcon> = {
  file_analysis: FileSearch, hash_file: Hash, hash_text: Hash, hash_identify: Hash, hash_compare: Hash,
  defender_scan: ShieldCheck, yara_scan: FileSearch, quarantine: ShieldCheck, restore: RefreshCw,
  ip_lookup: Earth, domain_lookup: Link2, reputation_lookup: Globe,
  forensics: MonitorCog, port_check: Network, discovery: Network,
};

export function Dashboard() {
  const { t, locale } = useI18n();
  const { navigate } = useApp();
  const snap = usePoll(async () => {
    const r = await window.blazma.system.snapshot();
    if (!r.ok) throw new Error(r.error);
    return r.data;
  }, 3000);
  const sec = usePoll(async () => {
    const r = await window.blazma.system.security();
    if (!r.ok) throw new Error(r.error);
    return r.data;
  }, 60000);
  const activity = usePoll(() => window.blazma.activity.recent(6), 10000);
  const qCount = usePoll(async () => {
    const r = await window.blazma.quarantine.list();
    return r.ok ? r.data.length : null;
  }, 15000);

  const [cpuHist, setCpuHist] = useState<number[]>([]);
  const lastSnap = useRef<SystemSnapshot | null>(null);
  useEffect(() => {
    const s = snap.data;
    if (!s || s === lastSnap.current) return;
    lastSnap.current = s;
    if (s.cpu.usagePercent !== null) setCpuHist((h) => [...h.slice(-(HISTORY - 1)), s.cpu.usagePercent!]);
  }, [snap.data]);

  const s = snap.data;
  const loading = !s;
  const activeIfaces = s?.interfaces.filter((i) => !i.internal && i.family === 'IPv4') ?? [];

  return (
    <div className="page" style={{ position: 'relative' }}>
      <Constellation />
      <div className="page-head" style={{ position: 'relative' }}>
        <div>
          <h1 className="page-title">{t('dashboard.title')}</h1>
          <div className="page-sub">{t('dashboard.subtitle')}</div>
        </div>
      </div>

      {snap.error && !s ? (
        <Card><ErrorState code={snap.error} onRetry={snap.reload} /></Card>
      ) : (
        <div className="grid g-4">
          <StatCard
            icon={Monitor} tone="blue" label={t('dashboard.os')} loading={loading}
            value={s?.osName}
            meta={s && (<>{t('dashboard.version', { v: '' })}<Ltr>{s.osVersion}</Ltr>{s.osBuild && <> · {t('dashboard.build', { b: '' })}<Ltr>{s.osBuild}</Ltr></>}</>)}
          />
          <StatCard
            icon={Cpu} tone="green" label={t('dashboard.cpu')} loading={loading}
            value={s?.cpu.model}
            meta={s && (
              <>
                {s.cpu.physicalCores ? t('dashboard.coresThreads', { cores: s.cpu.physicalCores, threads: s.cpu.logicalCores }) : t('dashboard.threadsOnly', { threads: s.cpu.logicalCores })}
                {s.cpu.speedMHz > 0 && <> · {t('dashboard.ghz', { ghz: (s.cpu.speedMHz / 1000).toFixed(1) })}</>}
              </>
            )}
          />
          <StatCard
            icon={MemoryStick} tone="cyan" label={t('dashboard.ram')} loading={loading}
            value={s && formatBytes(t, s.memory.totalBytes, 0)}
            bar={s?.memory.usedPercent}
            meta={s && t('dashboard.usedOf', { used: formatBytes(t, s.memory.totalBytes - s.memory.freeBytes), pct: Math.round(s.memory.usedPercent) })}
          />
          <StatCard
            icon={HardDrive} tone="purple" label={s?.disk ? `${t('dashboard.disk')} (${s.disk.mount})` : t('dashboard.disk')} loading={loading}
            value={s?.disk ? formatBytes(t, s.disk.totalBytes, 0) : t('common.notAvailable')}
            bar={s?.disk?.usedPercent}
            meta={s?.disk ? t('dashboard.usedOf', { used: formatBytes(t, s.disk.totalBytes - s.disk.freeBytes), pct: Math.round(s.disk.usedPercent) }) : undefined}
          />

          <div className="card span-3" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 18 }}>
            <PublicIp />
            <div className="row" style={{ gap: 14, alignItems: 'flex-start', borderInlineStart: '1px solid var(--border)', paddingInlineStart: 18 }}>
              <IconTile icon={Router} tone="cyan" />
              <div style={{ minWidth: 0 }}>
                <div className="stat-label">{t('dashboard.localIp')}</div>
                {loading ? <Skeleton w={120} h={18} style={{ marginTop: 5 }} /> : (
                  <div className="stat-value">{s?.primaryIPv4 ? <Ltr mono>{s.primaryIPv4}</Ltr> : <span className="muted" style={{ fontSize: 14 }}>{t('dashboard.noLocalIp')}</span>}</div>
                )}
                {s && <div className="row stat-meta" style={{ marginTop: 4 }}><Dot tone={s.networkUp ? 'green' : 'amber'} />{t(s.networkUp ? 'dashboard.networkUp' : 'dashboard.networkDown')}</div>}
              </div>
            </div>
            <div className="row" style={{ gap: 14, alignItems: 'flex-start', borderInlineStart: '1px solid var(--border)', paddingInlineStart: 18 }}>
              <IconTile icon={Wifi} tone="green" />
              <div style={{ minWidth: 0 }}>
                <div className="stat-label">{t('dashboard.networkStatus')}</div>
                {loading ? <Skeleton w={100} h={18} style={{ marginTop: 5 }} /> : (
                  <div className="stat-value" style={{ fontSize: 15 }}>{t('dashboard.interfaces', { count: activeIfaces.length })}</div>
                )}
                <div className="chip-list" style={{ marginTop: 6 }}>
                  {activeIfaces.slice(0, 3).map((i) => <span key={i.name + i.address} className="chip"><Ltr>{i.name}</Ltr></span>)}
                </div>
                <div className="tiny dim" style={{ marginTop: 6 }}>{t('dashboard.networkLocalNote')}</div>
              </div>
            </div>
          </div>

          <Card
            title={t('dashboard.systemStatus')} icon={ShieldCheck} tone="green"
            actions={<button className="icon-btn" style={{ width: 30, height: 30 }} title={t('common.refresh')} aria-label={t('common.refresh')} onClick={sec.reload}><RefreshCw size={14} /></button>}
          >
            <SecurityList sec={sec.data} snap={s} qCount={qCount.data ?? null} />
          </Card>
        </div>
      )}

      <div style={{ margin: '28px 0 14px' }}>
        <h2 className="section-title">{t('dashboard.quickTools')}</h2>
        <div className="page-sub small">{t('dashboard.quickToolsSub')}</div>
      </div>
      <div className="grid g-4">
        {TOOLS.map((tool) => {
          const disabled = tool.phase !== undefined;
          return (
            <button
              key={tool.id}
              className={`card tool ${disabled ? 'disabled' : ''}`}
              disabled={disabled}
              title={disabled ? t('nav.plannedTooltip', { phase: tool.phase! }) : undefined}
              onClick={() => navigate(tool.to)}
            >
              <IconTile icon={tool.icon} tone={tool.tone} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="tool-title">{t(`tools.${tool.id}.title`)}</div>
                <div className="tool-desc">{t(`tools.${tool.id}.desc`)}</div>
              </div>
              {disabled ? (
                <span className="nav-soon tool-phase nowrap">{t('common.phase', { phase: tool.phase! })}</span>
              ) : (
                <ChevronRight size={18} className="chev flip-rtl" />
              )}
            </button>
          );
        })}
      </div>

      <div className="grid g-2" style={{ marginTop: 20 }}>
        <Card title={t('dashboard.recentActivity')} subtitle={t('dashboard.recentActivitySub')} icon={Activity} tone="blue">
          {!activity.data ? (
            <div className="col">{[0, 1, 2].map((i) => <Skeleton key={i} h={32} />)}</div>
          ) : activity.data.length === 0 ? (
            <EmptyState title={t('dashboard.noActivity')} hint={t('dashboard.noActivityHint')} />
          ) : (
            <div className="col" style={{ gap: 4 }}>
              {activity.data.map((a) => {
                const Icon = ACTIVITY_ICON[a.kind];
                return (
                  <div key={a.id} className="row" style={{ padding: '8px 4px', borderBottom: '1px solid rgba(96,140,220,0.07)' }}>
                    <Icon size={16} color="var(--primary)" />
                    <span style={{ width: 130 }} className="small">{t(`activity.kind.${a.kind}`)}</span>
                    <span className="small" style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><Ltr>{a.subject}</Ltr></span>
                    <span className="tiny dim nowrap">{formatDateTime(locale, a.timestamp)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        <Card title={t('dashboard.systemOverview')} subtitle={t('dashboard.systemOverviewSub')} icon={MonitorCog} tone="purple">
          <div className="row" style={{ justifyContent: 'space-around', flexWrap: 'wrap', gap: 10 }}>
            <Gauge value={s?.cpu.usagePercent ?? null} label={t('dashboard.cpuUsage')} color="#2f86ff" />
            <Gauge value={s?.memory.usedPercent ?? null} label={t('dashboard.ramUsage')} color="#22d3a0" />
            <Gauge value={s?.disk?.usedPercent ?? null} label={t('dashboard.diskUsage')} color="#8b5cf6" />
          </div>
          <div style={{ marginTop: 14 }}>
            <div className="row tiny dim" style={{ marginBottom: 4 }}>
              <span>{cpuHist.length >= 2 ? t('dashboard.cpuHistory', { n: cpuHist.length }) : t('dashboard.sampling')}</span>
              <span className="spacer" />
              {s && s.processCount !== null && <span>{t('dashboard.processes')}: <Ltr>{s.processCount}</Ltr></span>}
              {s && <span>· {t('dashboard.uptime')}: {formatDuration(t, s.uptimeSec * 1000)}</span>}
            </div>
            <Sparkline values={cpuHist} color="#2f86ff" height={44} />
          </div>
        </Card>
      </div>
    </div>
  );
}
