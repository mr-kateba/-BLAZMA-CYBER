import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, CircleAlert, CircleCheck, Puzzle, RefreshCw, TriangleAlert } from 'lucide-react';
import type { BrowserExtension, ExtensionAudit, ExtensionRisk } from '../../shared/api';
import { Badge, Card, EmptyState, ErrorState, IconTile, Ltr, Notice, Skeleton, Toggle, type Tone } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

const TONE: Record<ExtensionRisk, Tone> = { high: 'red', medium: 'amber', low: 'green' };
const ICON = { high: CircleAlert, medium: TriangleAlert, low: CircleCheck } as const;
const FLAG_TONE = (f: string): Tone => (['sideloaded', 'external', 'debugger', 'unsigned'].includes(f) ? 'red' : f === 'policy' ? 'gray' : 'amber');

export function BrowserExtensions() {
  const { t, locale } = useI18n();
  const [state, setState] = useState<{ loading: boolean; audit?: ExtensionAudit; error?: string }>({ loading: true });
  const [onlyBroad, setOnlyBroad] = useState(false);

  const run = useCallback(async () => {
    setState({ loading: true });
    const r = await window.blazma.extensions.audit();
    setState(r.ok ? { loading: false, audit: r.data } : { loading: false, error: r.error });
  }, []);
  useEffect(() => void run(), [run]);

  const a = state.audit;
  const list = a ? a.extensions.filter((e) => !onlyBroad || e.risk !== 'low') : [];
  const count = (r: ExtensionRisk) => a?.extensions.filter((e) => e.risk === r).length ?? 0;

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={Puzzle} tone="blue" />
        <div>
          <h1 className="page-title">{t('ext.title')}</h1>
          <div className="page-sub">{t('ext.subtitle')}</div>
        </div>
        <span className="spacer" />
        <button className="btn" onClick={() => void run()} disabled={state.loading}><RefreshCw size={15} /> {t('ext.rescan')}</button>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue">{t('ext.readOnly')}</Notice>
        {state.loading && <Card><Skeleton h={120} /></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => void run()} /></Card>}

        {a && a.browsers.length === 0 && <Card><EmptyState icon={Puzzle} title={t('ext.noBrowsers')} hint={t('ext.noBrowsersHint')} /></Card>}

        {a && a.browsers.length > 0 && (
          <>
            <Card>
              <div className="col" style={{ gap: 10 }}>
                <div className="row-wrap" style={{ gap: 8 }}>
                  <Badge tone="red" icon={CircleAlert}>{t('ext.count.high', { n: count('high') })}</Badge>
                  <Badge tone="amber" icon={TriangleAlert}>{t('ext.count.medium', { n: count('medium') })}</Badge>
                  <Badge tone="green" icon={CircleCheck}>{t('ext.count.low', { n: count('low') })}</Badge>
                </div>
                <div className="small muted">
                  {t('ext.browsersFound', { list: a.browsers.map((b) => `${t(`ext.browser.${b.browser}`)} (${b.profiles})`).join(' · ') })}
                </div>
                <div className="row" style={{ gap: 10 }}>
                  <Toggle checked={onlyBroad} onChange={setOnlyBroad} label={t('ext.onlyBroad')} />
                  <span className="small">{t('ext.onlyBroad')}</span>
                </div>
                <div className="tiny dim">{t('ext.checkedAt', { time: formatDateTime(locale, a.collectedAt) })}</div>
              </div>
            </Card>

            <Card title={t('ext.listTitle', { count: list.length })} subtitle={t('ext.listSub')} explain="extension_permissions">
              {list.length === 0 ? <div className="muted small">{t('ext.none')}</div> : (
                <div className="col" style={{ gap: 8 }}>
                  {list.map((e) => <ExtensionRow key={`${e.browser}-${e.profile}-${e.id}`} e={e} />)}
                </div>
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function ExtensionRow({ e }: { e: BrowserExtension }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const Icon = ICON[e.risk];
  return (
    <div className={`devsec-row tone-${TONE[e.risk]}`}>
      <button className="devsec-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon size={18} className="devsec-icon" />
        <span className="devsec-title"><Ltr>{e.name}</Ltr></span>
        <span className="small dim">{t(`ext.browser.${e.browser}`)} · <Ltr>{e.profile}</Ltr></span>
        <span className="spacer" />
        {e.enabled === false && <Badge tone="gray">{t('ext.disabled')}</Badge>}
        <Badge tone={TONE[e.risk]}>{t(`ext.risk.${e.risk}`)}</Badge>
        <ChevronDown size={16} className={`devsec-chevron ${open ? 'open' : ''}`} />
      </button>
      {e.flags.length > 0 && (
        <div className="chip-list devsec-detail">
          {e.flags.map((f) => <Badge key={f} tone={FLAG_TONE(f)}>{t(`ext.flag.${f}`)}</Badge>)}
        </div>
      )}
      {open && (
        <div className="devsec-body">
          {e.flags.length > 0 && (
            <ul className="linksum-list">
              {e.flags.map((f) => <li key={f} className={`tone-${FLAG_TONE(f) === 'gray' ? 'gray' : FLAG_TONE(f)}`}>{t(`ext.flagWhy.${f}`)}</li>)}
            </ul>
          )}
          <dl className="kv">
            <dt>{t('ext.id')}</dt><dd><Ltr mono breakAll>{e.id}</Ltr></dd>
            <dt>{t('ext.version')}</dt><dd><Ltr mono>{e.version ?? '—'}</Ltr></dd>
            <dt>{t('ext.source')}</dt><dd>{t(`ext.sourceName.${e.source}`)}</dd>
            {e.permissions.length > 0 && <><dt>{t('ext.permissions')}</dt><dd><div className="chip-list">{e.permissions.map((p) => <span key={p} className="chip"><Ltr mono>{p}</Ltr></span>)}</div></dd></>}
            {e.hosts.length > 0 && <><dt>{t('ext.sites')}</dt><dd><div className="chip-list">{e.hosts.slice(0, 30).map((h) => <span key={h} className="chip"><Ltr mono>{h}</Ltr></span>)}</div></dd></>}
          </dl>
          <div className="small"><strong>{t('ext.howRemove')}</strong> {t(`ext.remove.${e.browser === 'firefox' ? 'firefox' : 'chromium'}`, { page: e.browser === 'edge' ? 'edge://extensions' : e.browser === 'brave' ? 'brave://extensions' : e.browser === 'vivaldi' ? 'vivaldi://extensions' : e.browser === 'opera' ? 'opera://extensions' : 'chrome://extensions' })}</div>
          <div className="tiny dim">{t('ext.disclaimer')}</div>
        </div>
      )}
    </div>
  );
}
