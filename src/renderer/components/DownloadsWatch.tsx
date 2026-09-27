import { useEffect, useState } from 'react';
import { DownloadCloud, FileSearch } from 'lucide-react';
import type { DownloadEvent, DownloadsWatchState } from '../../shared/api';
import { Badge, Card, Ltr, Toggle, type Tone } from './ui';
import { useApp } from './AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const VERDICT_TONE: Record<NonNullable<DownloadEvent['verdict']>, Tone> = { no_detections: 'green', unknown: 'gray', suspicious: 'amber', malicious: 'red' };

/** Dashboard card: opt-in watcher of the Downloads folder (static analysis only, while Blazma is open). */
export function DownloadsWatchCard() {
  const { t, locale } = useI18n();
  const { settings, updateSettings, analyzeFile } = useApp();
  const [s, setS] = useState<DownloadsWatchState | null>(null);
  useEffect(() => {
    void window.blazma.downloads.state().then((r) => r.ok && setS(r.data));
    return window.blazma.downloads.onState(setS);
  }, []);
  const on = settings.watchDownloads;
  return (
    <Card title={t('downloads.title')} subtitle={t('downloads.subtitle')} icon={DownloadCloud} tone="cyan" explain="downloads_watch"
      actions={<Toggle checked={on} onChange={(v) => void updateSettings({ watchDownloads: v })} label={t('downloads.toggle')} />}>
      <div className="col" style={{ gap: 8 }}>
        <div className="small muted">{on ? (s?.error ? t(`errors.${s.error}`) : t('downloads.on')) : t('downloads.off')}{on && s?.folder && !s.error && <Ltr mono className="small">{s.folder}</Ltr>}</div>
        {on && s && s.recent.length === 0 && <div className="tiny dim">{t('downloads.none')}</div>}
        {s && s.recent.length > 0 && (
          <div className="col" style={{ gap: 4 }}>
            {s.recent.slice(0, 8).map((e) => (
              <div key={e.id} className="row" style={{ gap: 8, padding: '6px 2px', borderBottom: '1px solid rgba(96,140,220,0.07)' }}>
                <span className="small" style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><Ltr>{e.name}</Ltr></span>
                {e.status === 'done' && e.verdict ? <Badge tone={VERDICT_TONE[e.verdict]}>{t(`verdict.${e.verdict}`)}</Badge>
                  : e.status === 'failed' ? <Badge tone="gray">{t(`errors.${e.error ?? 'unknown'}`)}</Badge>
                  : <Badge tone="blue">{t(`downloads.status.${e.status}`)}</Badge>}
                <span className="tiny dim nowrap">{formatDateTime(locale, e.at)}</span>
                {e.status === 'done' && <button className="btn sm" aria-label={t('downloads.details')} title={t('downloads.details')} onClick={() => analyzeFile(e.path)}><FileSearch size={13} /></button>}
              </div>
            ))}
          </div>
        )}
        {on && <div className="tiny dim">{t('downloads.note')}</div>}
      </div>
    </Card>
  );
}

/** Opens File Analyzer when the user clicks a "suspicious download" notification. */
export function DownloadsOpenListener() {
  const { analyzeFile } = useApp();
  useEffect(() => window.blazma.downloads.onOpen((ev) => analyzeFile(ev.path)), [analyzeFile]);
  return null;
}
