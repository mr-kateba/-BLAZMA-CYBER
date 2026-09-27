import { CalendarClock, CircleDot } from 'lucide-react';
import { Card, Badge, IconTile } from '../components/ui';
import { useI18n } from '../i18n/I18nProvider';
import type { NavItem } from '../nav';

/**
 * Shown for modules that are on the roadmap but not implemented. It explains what is coming and
 * deliberately contains NO action buttons, so nothing can look functional before it is.
 */
export function PlannedModule({ item }: { item: NavItem }) {
  const { t } = useI18n();
  const phase = item.planned?.phase ?? 0;
  const items = item.planned ? t(item.planned.itemsKey).split(' · ') : [];
  return (
    <div className="page">
      <div className="page-head">
        <IconTile icon={item.icon} tone="purple" />
        <div>
          <h1 className="page-title">{t(item.labelKey)}</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <Badge tone="purple" icon={CalendarClock}>{t('common.comingSoon', { phase })}</Badge>
          </div>
        </div>
      </div>
      <Card title={t('planned.title')} className="span-2" style={{ maxWidth: 820 }}>
        <p className="muted" style={{ marginTop: 0 }}>{t('planned.body', { phase })}</p>
        <h4 style={{ margin: '18px 0 10px', fontSize: 14 }}>{t('planned.willInclude')}</h4>
        <ul style={{ margin: 0, paddingInlineStart: 0, listStyle: 'none', display: 'grid', gap: 9 }}>
          {items.map((x) => (
            <li key={x} className="row" style={{ alignItems: 'flex-start' }}>
              <CircleDot size={14} color="var(--cyan)" style={{ marginTop: 4, flexShrink: 0 }} />
              <span>{x}</span>
            </li>
          ))}
        </ul>
        <p className="dim small" style={{ marginBottom: 0, marginTop: 18 }}>{t('planned.roadmap')}</p>
      </Card>
    </div>
  );
}
