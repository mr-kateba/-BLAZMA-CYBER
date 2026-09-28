import { useCallback, useEffect, useState } from 'react';
import { ClipboardPaste, KeyRound, QrCode, ScanSearch, ShieldAlert, ShieldCheck } from 'lucide-react';
import { classifyQrContent, type QrContent } from '../../core/qr-content';
import { Badge, Card, ErrorState, FileDrop, IconTile, Ltr, Notice, Progress, type Tone } from '../components/ui';
import { KV } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { decodeQr } from '../qr-decode';

const LEVEL_TONE: Record<QrContent['level'], Tone> = { risky: 'red', caution: 'amber', no_red_flags: 'green' };
/** Values that are technical (addresses, numbers): kept left-to-right. */
const LTR_FIELDS = new Set(['host', 'address', 'amount', 'currency', 'number', 'coordinates', 'to', 'account']);
/** Values that are codes to translate (qr.fieldValue.*). */
const CODED: Record<string, string[]> = { security: ['open'], hidden: ['yes'], password: ['present'] };

type State = { loading?: boolean; result?: QrContent; notFound?: boolean; error?: string };

export function QrCheck() {
  const { t } = useI18n();
  const { openWith } = useApp();
  const [state, setState] = useState<State>({});

  const fromBytes = useCallback(async (get: () => Promise<{ ok: true; data: Uint8Array } | { ok: false; error: string }>) => {
    setState({ loading: true });
    const r = await get();
    if (!r.ok) return setState({ error: r.error });
    try {
      const text = await decodeQr(r.data);
      setState(text === null ? { notFound: true } : { result: classifyQrContent(text) });
    } catch {
      setState({ error: 'qr_decode_failed' });
    }
  }, []);
  const fromPath = (path: string) => void fromBytes(() => window.blazma.qr.readImage(path));
  const fromClipboard = () => void fromBytes(() => window.blazma.qr.clipboardImage());

  // Ctrl+V anywhere on the page: the pasted image goes through the same size checks in main.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return;
      if (!e.clipboardData || ![...e.clipboardData.items].some((i) => i.type.startsWith('image/'))) return;
      e.preventDefault();
      fromClipboard();
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
  });

  const r = state.result;
  const fieldValue = (key: string, value: string) => {
    if (CODED[key]?.includes(value)) return t(`qr.fieldValue.${value}`);
    return LTR_FIELDS.has(key) ? <Ltr mono>{value}</Ltr> : <bdi>{value}</bdi>;
  };

  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={QrCode} tone="amber" />
        <div>
          <h1 className="page-title">{t('qr.title')}</h1>
          <div className="page-sub">{t('qr.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue" icon={ShieldCheck}>{t('qr.localOnly')}</Notice>

        {!r && !state.loading && (
          <>
            <FileDrop onFile={fromPath} onBrowse={() => void window.blazma.qr.pick().then((p) => { if (p) fromPath(p); })} title={t('qr.dropTitle')} hint={t('qr.dropHint')} activeText={t('qr.dropActive')} browseLabel={t('qr.pickImage')} />
            <div className="row" style={{ gap: 10 }}>
              <button className="btn" onClick={fromClipboard}><ClipboardPaste size={15} /> {t('qr.paste')}</button>
            </div>
          </>
        )}

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('qr.decoding')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}
        {state.notFound && (
          <Card>
            <Notice tone="amber" icon={ScanSearch}>
              <strong>{t('qr.notFound')}</strong> {t('qr.notFoundHint')}
            </Notice>
            <button className="btn sm" style={{ marginTop: 10 }} onClick={() => setState({})}>{t('qr.another')}</button>
          </Card>
        )}

        {r && (
          <>
            <Card title={t('qr.verdictTitle')} icon={r.level === 'risky' ? ShieldAlert : ShieldCheck} tone={LEVEL_TONE[r.level]} actions={<button className="btn sm" onClick={() => setState({})}>{t('qr.another')}</button>}>
              <div className="col" style={{ gap: 10 }}>
                <div className="row" style={{ gap: 10 }}>
                  <Badge tone={LEVEL_TONE[r.level]}>{t(`qr.level.${r.level}`)}</Badge>
                  <span className="small muted">{t(`qr.kind.${r.kind}`)}</span>
                </div>
                <ul className="linksum-list">
                  {r.signals.map((s) => <li key={s.key} className={`tone-${s.tone}`}>{t(`qr.signal.${s.key}`, s.vars)}</li>)}
                </ul>
                <div className="tiny dim">{t('qr.disclaimer')}</div>
              </div>
            </Card>

            <Card title={t('qr.contentTitle')} icon={QrCode} tone="blue">
              <div className="col" style={{ gap: 12 }}>
                {r.fields.length > 0 && (
                  <dl className="kv">
                    {r.fields.map((f) => <KV key={f.key} label={t(`qr.field.${f.key}`)}>{fieldValue(f.key, f.value)}</KV>)}
                  </dl>
                )}
                {r.display === null ? (
                  <Notice tone="amber" icon={KeyRound}>{t('qr.secretHidden')}</Notice>
                ) : (
                  <div>
                    <div className="small muted" style={{ marginBottom: 4 }}>{t('qr.raw')}</div>
                    <Ltr mono breakAll className="qr-raw">{r.display}</Ltr>
                  </div>
                )}
              </div>
            </Card>

            {r.actions.length > 0 && (
              <Card title={t('qr.actionsTitle')} icon={ScanSearch} tone="gray">
                <div className="small muted" style={{ marginBottom: 10 }}>{t('qr.actionsHint')}</div>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                  {r.actions.map((a) => (
                    <button key={`${a.page}:${a.action}`} className="btn sm" onClick={() => openWith(a.page, a.value, a.mode)}>{t(`smart.action.${a.action}`)}</button>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
