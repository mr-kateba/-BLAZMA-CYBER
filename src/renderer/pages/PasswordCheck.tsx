import { useMemo, useState } from 'react';
import { Eye, EyeOff, KeySquare, Lightbulb, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import type { PwnedResult } from '../../shared/api';
import { passwordTips } from '../../core/password-tips';
import { Badge, Card, ErrorState, IconTile, Notice, Progress } from '../components/ui';
import { OfflineBanner } from '../components/intel';
import { useI18n } from '../i18n/I18nProvider';
import { formatDateTime } from '../format';

export function PasswordCheck() {
  const { t, locale } = useI18n();
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const [state, setState] = useState<{ loading?: boolean; result?: PwnedResult; error?: string }>({});
  const local = useMemo(() => (pw ? passwordTips(pw) : null), [pw]);

  const check = async () => {
    const value = pw;
    // The password is cleared from the page as soon as it is sent; results never contain it.
    setPw('');
    setShow(false);
    setState({ loading: true });
    const r = await window.blazma.password.checkPwned(value);
    setState(r.ok ? { result: r.data } : { error: r.error });
  };

  const r = state.result;
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={KeySquare} tone="purple" />
        <div>
          <h1 className="page-title">{t('pwned.title')}</h1>
          <div className="page-sub">{t('pwned.subtitle')}</div>
        </div>
      </div>

      <div className="col" style={{ gap: 16 }}>
        <OfflineBanner />
        <Notice tone="blue" icon={ShieldCheck}>{t('pwned.privacy')}</Notice>

        <Card title={t('pwned.inputTitle')} icon={KeySquare} tone="purple" explain="k_anonymity">
          <form
            className="col"
            style={{ gap: 10 }}
            onSubmit={(e) => {
              e.preventDefault();
              if (pw && !state.loading) void check();
            }}
          >
            <div className="row" style={{ gap: 8 }}>
              <input
                className="input mono"
                dir="ltr"
                style={{ flex: 1 }}
                type={show ? 'text' : 'password'}
                autoComplete="off"
                spellCheck={false}
                maxLength={1024}
                value={pw}
                aria-label={t('pwned.inputLabel')}
                placeholder={t('pwned.placeholder')}
                onChange={(e) => setPw(e.target.value)}
              />
              <button type="button" className="btn" aria-label={t(show ? 'pwned.hide' : 'pwned.show')} title={t(show ? 'pwned.hide' : 'pwned.show')} onClick={() => setShow((v) => !v)}>
                {show ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
              <button type="submit" className="btn primary" disabled={!pw || state.loading}>{t('pwned.check')}</button>
            </div>
            <div className="tiny dim">{t('pwned.clearedNote')}</div>
          </form>
        </Card>

        {local && (
          <Card title={t('pwned.tipsTitle')} icon={Lightbulb} tone={local.tips.length ? 'amber' : 'green'} subtitle={t('pwned.tipsSub', { length: local.length, kinds: local.kinds })}>
            {local.tips.length === 0 ? (
              <div className="small">{t('pwned.noTips')}</div>
            ) : (
              <ul className="linksum-list">
                {local.tips.map((k) => <li key={k} className="tone-amber">{t(`pwned.tip.${k}`)}</li>)}
              </ul>
            )}
          </Card>
        )}

        {state.loading && <Card><Progress indeterminate /><div className="small muted" style={{ marginTop: 8 }}>{t('pwned.checking')}</div></Card>}
        {state.error && <Card><ErrorState code={state.error} onRetry={() => setState({})} /></Card>}

        {r && (
          <Card title={t('pwned.resultTitle')} icon={r.found ? ShieldAlert : ShieldQuestion} tone={r.found ? 'red' : 'green'} actions={<button className="btn sm" onClick={() => setState({})}>{t('pwned.another')}</button>}>
            <div className="col" style={{ gap: 10 }}>
              <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                <Badge tone={r.found ? 'red' : 'green'}>{t(r.found ? 'pwned.found' : 'pwned.notFound')}</Badge>
                {r.found && <strong>{t('pwned.count', { count: r.count.toLocaleString(locale) })}</strong>}
              </div>
              <div className="small">{t(r.found ? 'pwned.foundAdvice' : 'pwned.notFoundAdvice')}</div>
              <div className="tiny dim">{t('pwned.source', { time: formatDateTime(locale, r.checkedAt) })}</div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
