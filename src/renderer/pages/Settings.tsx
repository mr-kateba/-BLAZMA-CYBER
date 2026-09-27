import { useEffect, useState } from 'react';
import { Cpu, Info, KeyRound, Lock, Settings as Gear, ShieldCheck } from 'lucide-react';
import type { ApiKeyService, AppInfo, Settings } from '../../shared/api';
import { Badge, Card, IconTile, Ltr, Notice, Tabs, Toggle, usePoll } from '../components/ui';
import { useApp } from '../components/AppContext';
import { useI18n } from '../i18n/I18nProvider';

type Tab = 'general' | 'privacy' | 'apiKeys' | 'engines' | 'about';

function Row({ title, desc, children }: { title: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="setting-row">
      <div className="setting-text">
        <div style={{ fontWeight: 500 }}>{title}</div>
        {desc && <div className="small dim">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

function Select<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: Array<{ v: T; label: string }> }) {
  return (
    <select className="select" style={{ width: 220 }} value={value} onChange={(e) => onChange(e.target.value as T)}>
      {options.map((o) => <option key={o.v} value={o.v}>{o.label}</option>)}
    </select>
  );
}

function General() {
  const { t } = useI18n();
  const { settings, updateSettings } = useApp();
  return (
    <Card>
      <Row title={t('settings.language')} desc={t('settings.languageDesc')}>
        <Select value={settings.language ?? 'en'} onChange={(v) => void updateSettings({ language: v })} options={[{ v: 'ar', label: 'العربية' }, { v: 'en', label: 'English' }]} />
      </Row>
      <Row title={t('settings.theme')}>
        <Select<Settings['theme']> value={settings.theme} onChange={(v) => void updateSettings({ theme: v })} options={[{ v: 'dark', label: t('settings.themeDark') }, { v: 'midnight', label: t('settings.themeMidnight') }]} />
      </Row>
      <Row title={t('settings.startPage')}>
        <Select<Settings['startPage']>
          value={settings.startPage}
          onChange={(v) => void updateSettings({ startPage: v })}
          options={[
            { v: 'dashboard', label: t('nav.dashboard') },
            { v: 'file-analyzer', label: t('nav.fileAnalyzer') },
            { v: 'hash-lab', label: t('nav.hashLab') },
            { v: 'privacy', label: t('nav.privacyCenter') },
          ]}
        />
      </Row>
      <Row title={t('settings.notifications')}>
        <Toggle checked={settings.notifications} label={t('settings.notifications')} onChange={(v) => void updateSettings({ notifications: v })} />
      </Row>
      <Row title={t('settings.reportLanguage')}>
        <Select value={settings.reportLanguage} onChange={(v) => void updateSettings({ reportLanguage: v })} options={[{ v: 'ar', label: 'العربية' }, { v: 'en', label: 'English' }]} />
      </Row>
    </Card>
  );
}

function Privacy() {
  const { t } = useI18n();
  const { settings, updateSettings } = useApp();
  return (
    <Card>
      <Row title={t('settings.offlineMode')} desc={t('privacy.offlineDesc')}>
        <Toggle checked={settings.offlineMode} label={t('settings.offlineMode')} onChange={(v) => void updateSettings({ offlineMode: v })} />
      </Row>
      <Row title={t('settings.keepHistory')} desc={t('settings.keepHistoryDesc')}>
        <Toggle checked={settings.keepHistory} label={t('settings.keepHistory')} onChange={(v) => void updateSettings({ keepHistory: v })} />
      </Row>
      <Row title={t('settings.logLevel')} desc={t('settings.logNote')}>
        <Select<Settings['logLevel']> value={settings.logLevel} onChange={(v) => void updateSettings({ logLevel: v })} options={[{ v: 'INFO', label: t('settings.logLevelInfo') }, { v: 'DEBUG', label: t('settings.logLevelDebug') }]} />
      </Row>
    </Card>
  );
}

const SERVICES: ApiKeyService[] = ['virustotal', 'abuseipdb', 'shodan', 'censys'];

function ApiKeys({ secure }: { secure: boolean | null }) {
  const { t } = useI18n();
  const { toast, confirm } = useApp();
  const status = usePoll(() => window.blazma.secrets.status(), null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});

  return (
    <Card>
      <Notice icon={Lock}>{t('settings.apiKeysDesc')}</Notice>
      {secure === false && <div style={{ marginTop: 10 }}><Notice tone="red">{t('settings.secureUnavailable')}</Notice></div>}
      {SERVICES.map((s) => {
        const configured = status.data?.[s] ?? false;
        return (
          <Row key={s} title={t(`settings.service.${s}`)}>
            <Badge tone={configured ? 'green' : 'gray'}>{t(configured ? 'common.configured' : 'common.notConfigured')}</Badge>
            <input
              className="input mono"
              dir="ltr"
              type="password"
              autoComplete="off"
              style={{ width: 260 }}
              placeholder={t('settings.apiKeyPlaceholder')}
              value={drafts[s] ?? ''}
              disabled={secure === false}
              onChange={(e) => setDrafts((d) => ({ ...d, [s]: e.target.value }))}
            />
            <button
              className="btn primary sm"
              disabled={!drafts[s]?.trim() || secure === false}
              onClick={async () => {
                const r = await window.blazma.secrets.set(s, drafts[s] ?? '');
                if (r.ok) {
                  toast('green', t('settings.keySaved'));
                  setDrafts((d) => ({ ...d, [s]: '' }));
                  status.reload();
                } else toast('red', t(`errors.${r.error}`));
              }}
            >
              {t('common.save')}
            </button>
            {configured && (
              <button
                className="btn danger sm"
                onClick={async () => {
                  const name = t(`settings.service.${s}`);
                  if (!(await confirm({ title: t('privacy.confirmTitle'), body: t('privacy.confirmBody', { what: name }), confirmLabel: t('common.remove'), danger: true }))) return;
                  const r = await window.blazma.secrets.remove(s);
                  if (r.ok) {
                    toast('green', t('settings.keyRemoved'));
                    status.reload();
                  }
                }}
              >
                {t('common.remove')}
              </button>
            )}
          </Row>
        );
      })}
    </Card>
  );
}

function Engines() {
  const { t } = useI18n();
  const sec = usePoll(async () => {
    const r = await window.blazma.system.security();
    return r.ok ? r.data : null;
  }, null);
  const d = sec.data?.defender;
  const defenderBadge = !sec.data ? null : d?.available ? (
    <Badge tone="green">{t('settings.engineStatus.available')}</Badge>
  ) : (
    <Badge tone="amber">{t('settings.engineStatus.unavailable')}</Badge>
  );
  return (
    <Card>
      <p className="muted small" style={{ marginTop: 0 }}>{t('settings.enginesDesc')}</p>
      <Row title={t('settings.builtin')} desc={t('settings.builtinDesc')}>
        <Badge tone="green">{t('settings.engineStatus.available')}</Badge>
      </Row>
      <Row title="Microsoft Defender" desc={d && !d.available && d.reason ? t(`errors.${d.reason}`) : d?.signatureVersion ? t('status.signatures', { version: d.signatureVersion, age: d.signatureAgeDays ?? '?' }) : undefined}>
        {defenderBadge}
        <Badge tone="purple">{t('common.comingSoon', { phase: 2 })}</Badge>
      </Row>
      <Row title="YARA-X" desc={t('planned.modules.yara')}>
        <Badge tone="purple">{t('settings.engineStatus.planned')} · {t('common.phase', { phase: 2 })}</Badge>
      </Row>
      <Row title={t('nav.passwordRecovery')} desc={t('planned.modules.passwordRecovery')}>
        <Badge tone="purple">{t('settings.engineStatus.planned')} · {t('common.phase', { phase: 5 })}</Badge>
      </Row>
    </Card>
  );
}

function About({ info }: { info: AppInfo | null }) {
  const { t } = useI18n();
  return (
    <Card>
      {info && (
        <dl className="kv">
          <dt>{t('settings.version')}</dt><dd><Ltr>{info.version}</Ltr></dd>
          <dt>{t('settings.platform')}</dt><dd><Ltr>{info.platform}</Ltr></dd>
          <dt>{t('settings.electron')}</dt><dd><Ltr>{info.electron}</Ltr></dd>
          <dt>{t('settings.dataDir')}</dt><dd><Ltr mono breakAll className="small">{info.dataDir}</Ltr></dd>
        </dl>
      )}
      <p className="small dim" style={{ marginBottom: 0 }}>{t('settings.license')}</p>
    </Card>
  );
}

export function SettingsPage({ tab: initial }: { tab: Tab }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>(initial);
  const [info, setInfo] = useState<AppInfo | null>(null);
  useEffect(() => void window.blazma.app.info().then(setInfo), []);
  useEffect(() => setTab(initial), [initial]);
  const icons = { general: Gear, privacy: ShieldCheck, apiKeys: KeyRound, engines: Cpu, about: Info };
  return (
    <div className="page" style={{ maxWidth: 1000 }}>
      <div className="page-head">
        <IconTile icon={icons[tab]} tone="blue" />
        <div>
          <h1 className="page-title">{t('settings.title')}</h1>
          <div className="page-sub">{t('settings.subtitle')}</div>
        </div>
      </div>
      <Tabs<Tab> value={tab} onChange={setTab} items={(['general', 'privacy', 'apiKeys', 'engines', 'about'] as const).map((id) => ({ id, label: t(`settings.tab.${id}`) }))} />
      {tab === 'general' && <General />}
      {tab === 'privacy' && <Privacy />}
      {tab === 'apiKeys' && <ApiKeys secure={info ? info.secureStorageAvailable : null} />}
      {tab === 'engines' && <Engines />}
      {tab === 'about' && <About info={info} />}
    </div>
  );
}
