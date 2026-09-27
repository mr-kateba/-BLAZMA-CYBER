import type { MacMaker } from '../../shared/api';
import { Badge, Ltr } from './ui';
import { useI18n } from '../i18n/I18nProvider';

/** Manufacturer of a device (offline IEEE registry), or why there is none. */
export function DeviceMaker({ maker }: { maker: MacMaker | null | undefined }) {
  const { t } = useI18n();
  if (!maker) return <span className="dim">—</span>;
  if (maker.vendor) return <Ltr>{maker.vendor}</Ltr>;
  if (maker.kind === 'random') return <span title={t('net.maker.randomHint')}><Badge tone="purple">{t('net.maker.random')}</Badge></span>;
  return <span className="dim small">{t(`net.maker.${maker.kind}`)}</span>;
}
