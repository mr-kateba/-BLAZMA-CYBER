import { useEffect, useState } from 'react';
import { BadgeCheck, CircleCheck, CircleDashed, DoorOpen, FolderCheck, Power, Loader2, Puzzle, RefreshCw, ShieldAlert, ShieldCheck, Stethoscope, TriangleAlert, Wifi, type LucideIcon, FileText } from 'lucide-react';
import { deviceArea, extensionsArea, foldersArea, overall, portsArea, startupArea, tamperArea, wifiArea, type AreaResult, type AreaState, type CheckupArea, type CheckupSummary, type Part } from '../../core/checkup';
import type { ConnectionRow, ForensicsResult, Result } from '../../shared/api';
import { listeningServices } from '../../core/listening';
import { loadStartupReview } from './StartupApps';
import { Badge, Card, IconTile, Notice, type Tone } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime, newTaskId } from '../format';
import type { PageId } from '../nav';

const AREAS: Array<{ area: CheckupArea; icon: LucideIcon; page: PageId }> = [
  { area: 'device', icon: BadgeCheck, page: 'device-security' },
  { area: 'tamper', icon: ShieldAlert, page: 'device-security' },
  { area: 'startup', icon: Power, page: 'startup-apps' },
  { area: 'extensions', icon: Puzzle, page: 'browser-extensions' },
  { area: 'wifi', icon: Wifi, page: 'wifi' },
  { area: 'ports', icon: DoorOpen, page: 'open-ports' },
  { area: 'folders', icon: FolderCheck, page: 'file-integrity' },
];
const TONE: Record<AreaState, Tone> = { ok: 'green', attention: 'amber', problem: 'red', unavailable: 'gray' };

const part = <T,>(r: Result<T>): Part<T> => (r.ok ? { data: r.data } : { error: r.error });

export function Checkup() {
  const { t, locale, lang } = useI18n();
  const { navigate, toast } = useApp();
  const [saving, setSaving] = useState(false);
  const [results, setResults] = useState<Partial<Record<CheckupArea, AreaResult>>>({});
  const [current, setCurrent] = useState<CheckupArea | null>(null);
  const [doneAt, setDoneAt] = useState<string | null>(null);
  const [last, setLast] = useState<CheckupSummary | null>(null);
  useEffect(() => void window.blazma.checkup.last().then((r) => r.ok && setLast(r.data)), []);

  const run = async () => {
    setResults({});
    setDoneAt(null);
    const collected: AreaResult[] = [];
    const put = (r: AreaResult) => {
      collected.push(r);
      setResults((x) => ({ ...x, [r.area]: r }));
    };
    // One area at a time: several of these run PowerShell, and Windows answers faster in sequence.
    setCurrent('device');
    put(deviceArea(part(await window.blazma.device.security(true))));
    setCurrent('tamper');
    put(tamperArea(part(await window.blazma.device.tamper())));
    setCurrent('startup');
    const st = await loadStartupReview();
    put(startupArea('error' in st ? { error: st.error } : { data: st.items }));
    setCurrent('extensions');
    put(extensionsArea(part(await window.blazma.extensions.audit())));
    setCurrent('wifi');
    put(wifiArea(part(await window.blazma.wifi.report())));
    setCurrent('ports');
    const conns = await window.blazma.forensics.collect('connections');
    put(portsArea(conns.ok ? { data: listeningServices((conns.data as ForensicsResult<ConnectionRow>).rows) } : { error: conns.error }));
    setCurrent('folders');
    const watches = await window.blazma.fim.list();
    if (!watches.ok) put(foldersArea({ error: watches.error }));
    else {
      const checks = [];
      let error: string | null = null;
      for (const w of watches.data) {
        const r = await window.blazma.fim.check(w.id, newTaskId());
        if (r.ok) checks.push(r.data);
        else error ??= r.error;
      }
      put(foldersArea(error && checks.length === 0 ? { error } : { data: checks }));
    }
    setCurrent(null);
    setDoneAt(new Date().toISOString());
    const areas = collected.map((a) => ({ area: a.area, state: a.state, count: a.count }));
    void window.blazma.checkup.save({ areas }).then((r) => r.ok && setLast(r.data));
  };

  const saveReport = async (format: 'pdf' | 'html') => {
    setSaving(true);
    const areas = list.map((a) => ({ area: a.area, state: a.state, count: a.count, ...(a.reason ? { reason: a.reason } : {}), ...(a.vars ? { vars: a.vars } : {}) }));
    const r = await window.blazma.checkup.report({ areas }, lang === 'ar' ? 'ar' : 'en', format);
    setSaving(false);
    if (!r.ok) return toast('red', t(`errors.${r.error}`));
    toast('green', t('checkup.reportSaved'));
    void window.blazma.reports.open(r.data.id);
  };

  const list = AREAS.map((a) => results[a.area]).filter((x): x is AreaResult => !!x);
  const verdict = doneAt ? overall(list) : last?.verdict ?? null;
  const running = current !== null;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Stethoscope} tone="green" />
        <div>
          <h1 className="page-title">{t('checkup.title')}</h1>
          <div className="page-sub">{t('checkup.subtitle')}</div>
        </div>
      </div>
      <div className="col" style={{ gap: 16 }}>
        <Card className={`checkup-hero${verdict ? ` tone-${TONE[verdict]}` : ''}`}>
          <div className="row" style={{ gap: 18, flexWrap: 'wrap' }}>
            <div className="checkup-mark">
              {running ? <Loader2 size={34} className="spin" /> : verdict === 'ok' ? <ShieldCheck size={34} /> : verdict === 'problem' || verdict === 'attention' ? <TriangleAlert size={34} /> : <Stethoscope size={34} />}
            </div>
            <div className="col" style={{ gap: 4, flex: 1, minWidth: 220 }}>
              <strong className="checkup-verdict">{running ? t('checkup.running', { area: t(`checkup.area.${current}.title`) }) : verdict ? t(`checkup.verdict.${verdict}`) : t('checkup.ready')}</strong>
              <span className="small muted">{doneAt ? t('checkup.doneAt', { date: formatDateTime(locale, doneAt) }) : last ? t('checkup.lastAt', { date: formatDateTime(locale, last.at) }) : t('checkup.readyHint')}</span>
            </div>
            <button className="btn primary" disabled={running} onClick={() => void run()}>
              {doneAt || last ? <RefreshCw size={15} /> : <Stethoscope size={15} />} {doneAt || last ? t('checkup.again') : t('checkup.start')}
            </button>
          </div>
          {doneAt && !running && (
            <div className="row-wrap" style={{ gap: 8, marginTop: 14 }}>
              <button className="btn sm" disabled={saving} onClick={() => void saveReport('pdf')}><FileText size={13} /> {t('checkup.savePdf')}</button>
              <button className="btn sm" disabled={saving} onClick={() => void saveReport('html')}><FileText size={13} /> {t('checkup.saveHtml')}</button>
            </div>
          )}
        </Card>
        <Notice icon={ShieldCheck}>{t('checkup.readOnly')}</Notice>
        <div className="col" style={{ gap: 10 }}>
          {AREAS.map(({ area, icon: Icon, page }) => {
            const r = results[area];
            const busy = current === area;
            return (
              <div key={area} className={`devsec-row tone-${r ? TONE[r.state] : 'gray'}`}>
                <div className="devsec-head" style={{ cursor: 'default' }}>
                  <Icon size={18} className="devsec-icon" />
                  <div className="col" style={{ gap: 2, flex: 1, minWidth: 0 }}>
                    <span className="devsec-title">{t(`checkup.area.${area}.title`)}</span>
                    <span className="small muted">
                      {!r ? (busy ? t('checkup.checking') : t(`checkup.area.${area}.what`)) : r.state === 'unavailable' ? t(`errors.${r.reason}`) : t(`checkup.area.${area}.${r.state}`, { n: r.count, ...(r.vars ?? {}) })}
                    </span>
                  </div>
                  {busy ? <Loader2 size={16} className="spin" /> : r ? <Badge tone={TONE[r.state]}>{t(`checkup.state.${r.state}`)}</Badge> : <CircleDashed size={16} className="dim" />}
                  {r && r.state !== 'unavailable' && (
                    <button className="btn sm" onClick={() => navigate(page)}>{r.state === 'ok' ? <CircleCheck size={13} /> : null}{t('checkup.open')}</button>
                  )}
                  {r?.state === 'unavailable' && r.reason === 'no_watches' && (
                    <button className="btn sm" onClick={() => navigate('file-integrity')}>{t('checkup.addWatch')}</button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
