import { Crosshair } from 'lucide-react';
import { ATTACK_VERSION, attackMatrix } from '../../core/attack';
import { Card, Ltr } from './ui';
import { useApp } from './AppContext';
import { useI18n } from '../i18n/I18nProvider';

/** Observed MITRE ATT&CK techniques grouped by tactic (kill-chain order). Links open attack.mitre.org. */
export function AttackMatrix({ observed }: { observed: Array<{ id: string; count: number }> }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const cols = attackMatrix(observed);
  if (cols.length === 0) return null;
  const open = async (url: string) => {
    const r = await window.blazma.app.openLink(url);
    if (!r.ok) toast('red', t(`errors.${r.error}`));
  };
  return (
    <Card title={t('attack.title')} subtitle={t('attack.subtitle', { version: ATTACK_VERSION ?? '' })} icon={Crosshair} tone="purple" explain="attack">
      <div className="attack-matrix">
        {cols.map((c) => (
          <div key={c.tactic.id} className="attack-col">
            <div className="attack-tactic">{t(`evlog.tactic.${c.tactic.short.replace(/-/g, '_')}`)} <span className="tiny dim"><Ltr mono>{c.tactic.id}</Ltr></span></div>
            {c.techniques.map((x) => (
              <button key={x.id} type="button" className="attack-tech" title={t('attack.open')} onClick={() => void open(x.url)}>
                <Ltr mono className="tiny">{x.id}{x.replaces ? ` (${t('attack.was', { id: x.replaces })})` : ''}</Ltr>
                <Ltr className="small">{x.parentName ? `${x.parentName}: ${x.name}` : x.name}</Ltr>
                <span className="tiny dim">{t('attack.count', { n: x.count })}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className="tiny dim" style={{ marginTop: 8 }}>{t('attack.notice')}</div>
    </Card>
  );
}
