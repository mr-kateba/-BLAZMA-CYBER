import { useState } from 'react';
import { FileSearch, Link2, Mail, MailWarning, Paperclip, Route, ShieldAlert, ShieldCheck, UserRound } from 'lucide-react';
import type { EmailAnalysis } from '../../shared/api';
import { Badge, Card, DataTable, ErrorState, FileDrop, IconTile, Ltr, Notice, Progress, type Tone } from '../components/ui';
import { KV } from '../components/intel';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { formatBytes, formatDateTime } from '../format';

type Result = EmailAnalysis & { token: string };
const LEVEL_TONE: Record<Result['level'], Tone> = { risky: 'red', caution: 'amber', no_red_flags: 'green' };
const AUTH_TONE = (r: string): Tone => (r === 'pass' ? 'green' : r === 'fail' ? 'red' : r === 'softfail' ? 'amber' : 'gray');
const RED_LINK = new Set(['mismatch', 'ip', 'userinfo', 'script', 'invalid']);
const RED_ATT = new Set(['executable', 'double_extension', 'rtlo']);

export function EmailCheck() {
  const { t, locale } = useI18n();
  const { analyzeFile, toast } = useApp();
  const [state, setState] = useState<{ loading?: boolean; result?: Result; error?: string }>({});
  const [paste, setPaste] = useState('');

  const fromFile = async (path: string) => {
    setState({ loading: true });
    const r = await window.blazma.email.analyzeFile(path);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };
  const fromText = async () => {
    setState({ loading: true });
    const r = await window.blazma.email.analyzeText(paste);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };
  const inspectAttachment = async (index: number) => {
    if (!state.result) return;
    const r = await window.blazma.email.extractAttachment(state.result.token, index);
    if (r.ok) analyzeFile(r.data);
    else toast('red', t(`errors.${r.error}`));
  };

  const r = state.result;
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={MailWarning} tone="amber" />
        <div>
          <h1 className="page-title">{t('email.title')}</h1>
          <div className="page-sub">{t('email.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <Notice tone="blue" icon={ShieldCheck}>{t('email.localOnly')}</Notice>

        {!r && !state.loading && (
          <>
            <FileDrop onFile={(p) => void fromFile(p)} title={t('email.dropTitle')} hint={t('email.dropHint')} activeText={t('email.dropActive')} browseLabel={t('common.browse')} />
            <div className="small muted">{t('email.howToSave')}</div>
            <Card title={t('email.pasteTitle')} icon={Mail} tone="gray">
              <textarea className="input mono" dir="ltr" rows={6} style={{ width: '100%', resize: 'vertical' }} value={paste} placeholder={t('email.pastePlaceholder')} aria-label={t('email.pasteTitle')} onChange={(e) => setPaste(e.target.value)} />
              <button className="btn primary" style={{ marginTop: 10 }} disabled={!paste.trim()} onClick={() => void fromText()}>{t('email.analyze')}</button>
            </Card>
          </>
        )}

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('email.analyzing')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}

        {r && (
          <>
            <Card title={t('email.verdictTitle')} icon={r.level === 'risky' ? ShieldAlert : ShieldCheck} tone={LEVEL_TONE[r.level]} actions={<button className="btn sm" onClick={() => setState({})}>{t('email.another')}</button>}>
              <div className="col" style={{ gap: 10 }}>
                <div className="row" style={{ gap: 10 }}>
                  <Badge tone={LEVEL_TONE[r.level]}>{t(`email.level.${r.level}`)}</Badge>
                  <span className="small muted">{t(`email.levelHint.${r.level}`)}</span>
                </div>
                {r.signals.length > 0 && (
                  <ul className="linksum-list">
                    {r.signals.map((s) => <li key={s.key} className={`tone-${s.tone}`}>{t(`email.signal.${s.key}`, s.vars)}</li>)}
                  </ul>
                )}
                <div className="tiny dim">{t('email.disclaimer')}</div>
              </div>
            </Card>

            <div className="grid g-2">
              <Card title={t('email.sender')} icon={UserRound} tone="blue">
                <dl className="kv">
                  <KV label={t('email.subject')}>{r.subject ?? '—'}</KV>
                  <KV label={t('email.from')}>{r.from ? <><span>{r.from.name ?? ''}</span> <Ltr mono>{r.from.address ? `<${r.from.address}>` : ''}</Ltr></> : '—'}</KV>
                  <KV label={t('email.replyTo')}>{r.replyTo?.address ? <Ltr mono>{r.replyTo.address}</Ltr> : '—'}</KV>
                  <KV label={t('email.returnPath')}>{r.returnPath?.address ? <Ltr mono>{r.returnPath.address}</Ltr> : '—'}</KV>
                  <KV label={t('email.to')}>{r.to ? <Ltr mono>{r.to}</Ltr> : '—'}</KV>
                  <KV label={t('email.date')}>{formatDateTime(locale, r.date)}</KV>
                </dl>
              </Card>
              <Card title={t('email.auth')} explain="spf_dmarc" icon={ShieldCheck} tone="purple" subtitle={t('email.authSub')}>
                {r.auth.length === 0 ? <div className="muted small">{t('email.noAuth')}</div> : (
                  <div className="col" style={{ gap: 8 }}>
                    {r.auth.map((a) => (
                      <div key={a.method} className="row" style={{ gap: 10 }}>
                        <strong style={{ minWidth: 70 }}><Ltr>{a.method.toUpperCase()}</Ltr></strong>
                        <Badge tone={AUTH_TONE(a.result)}><Ltr>{a.result}</Ltr></Badge>
                        <span className="small muted">{t(`email.authMeaning.${a.result === 'pass' ? 'pass' : a.result === 'fail' ? 'fail' : a.result === 'softfail' ? 'softfail' : 'other'}`)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            <Card title={t('email.links', { count: r.links.length })} icon={Link2} tone={r.links.some((l) => l.flags.some((f) => RED_LINK.has(f))) ? 'red' : 'blue'} subtitle={t('email.linksSub')}>
              {r.links.length === 0 ? <div className="muted small">{t('email.noLinks')}</div> : (
                <DataTable
                  maxHeight={380}
                  rowKey={(l, i) => `${i}-${l.href}`}
                  rows={r.links}
                  columns={[
                    { key: 'text', label: t('email.linkShown'), render: (l) => (l.text ? <Ltr className="small">{l.text}</Ltr> : <span className="dim small">—</span>) },
                    { key: 'dest', label: t('email.linkGoesTo'), render: (l) => <div><Ltr mono className="small" breakAll>{l.host ?? l.href.slice(0, 80)}</Ltr><div className="tiny dim"><Ltr mono breakAll>{l.href.length > 120 ? `${l.href.slice(0, 120)}…` : l.href}</Ltr></div></div> },
                    { key: 'f', label: '', render: (l) => <div className="chip-list">{l.flags.map((f) => <Badge key={f} tone={RED_LINK.has(f) ? 'red' : 'amber'}>{t(`email.linkFlag.${f}`)}</Badge>)}</div> },
                  ]}
                />
              )}
            </Card>

            <Card title={t('email.attachments', { count: r.attachments.length })} icon={Paperclip} tone={r.attachments.some((a) => a.flags.some((f) => RED_ATT.has(f))) ? 'red' : 'blue'}>
              {r.attachments.length === 0 ? <div className="muted small">{t('email.noAttachments')}</div> : (
                <DataTable
                  rowKey={(a) => String(a.index)}
                  rows={r.attachments}
                  columns={[
                    { key: 'n', label: t('email.attName'), render: (a) => <div><Ltr>{a.name}</Ltr><div className="tiny dim"><Ltr mono>{a.contentType}</Ltr> · {formatBytes(t, a.size)}</div></div> },
                    { key: 'h', label: 'SHA-256', render: (a) => <Ltr mono className="tiny" breakAll>{a.sha256}</Ltr> },
                    { key: 'f', label: '', render: (a) => <div className="chip-list">{a.flags.map((f) => <Badge key={f} tone={RED_ATT.has(f) ? 'red' : 'amber'}>{t(`email.attFlag.${f}`)}</Badge>)}</div> },
                    { key: 'x', label: '', render: (a) => <button className="btn sm" onClick={() => void inspectAttachment(a.index)}><FileSearch size={13} /> {t('email.analyzeAttachment')}</button> },
                  ]}
                />
              )}
              <div className="tiny dim" style={{ marginTop: 8 }}>{t('email.attachmentNote')}</div>
            </Card>

            {r.received.length > 0 && (
              <Card title={t('email.route', { count: r.received.length })} icon={Route} tone="gray" subtitle={t('email.routeSub')}>
                <DataTable
                  rowKey={(h, i) => `${i}`}
                  rows={r.received}
                  columns={[
                    { key: 'f', label: t('email.hopFrom'), render: (h) => <Ltr mono className="small">{h.from ?? '—'}</Ltr> },
                    { key: 'b', label: t('email.hopBy'), render: (h) => <Ltr mono className="small">{h.by ?? '—'}</Ltr> },
                    { key: 'd', label: t('email.date'), render: (h) => <span className="small nowrap">{formatDateTime(locale, h.date)}</span> },
                  ]}
                />
              </Card>
            )}

            {r.textPreview && (
              <Card title={t('email.preview')} icon={Mail} tone="gray" subtitle={t('email.previewSub')}>
                <pre className="email-preview" dir="auto">{r.textPreview}</pre>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
