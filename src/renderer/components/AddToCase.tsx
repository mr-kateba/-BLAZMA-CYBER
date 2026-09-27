import { useState } from 'react';
import { FolderPlus, X } from 'lucide-react';
import type { CaseSummary, Evidence, EvidenceKind } from '../../shared/api';
import { useApp } from './AppContext';
import { useI18n } from '../i18n/I18nProvider';
import { Ltr } from './ui';

export interface EvidenceDraft {
  kind: EvidenceKind;
  value: string;
  label?: string | null;
  source: string;
  details?: Evidence['details'];
}

/** Button + picker that adds one or more pieces of evidence to an existing or new case. */
export function AddToCase({ items, small = true }: { items: EvidenceDraft[]; small?: boolean }) {
  const { t } = useI18n();
  const { toast } = useApp();
  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<CaseSummary[] | null>(null);
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState(false);

  const show = async () => {
    setOpen(true);
    const r = await window.blazma.cases.list();
    setCases(r.ok ? r.data.filter((c) => c.status === 'open') : []);
  };
  const addTo = async (caseId: string) => {
    setBusy(true);
    for (const it of items) {
      const r = await window.blazma.cases.addEvidence(caseId, it);
      if (!r.ok) {
        toast('red', t(`errors.${r.error}`));
        setBusy(false);
        return;
      }
    }
    setBusy(false);
    setOpen(false);
    toast('green', t('cases.added', { id: caseId }));
  };
  const createAndAdd = async () => {
    const r = await window.blazma.cases.create(newName.trim(), '', []);
    if (r.ok) await addTo(r.data.id);
    else toast('red', t(`errors.${r.error}`));
  };

  return (
    <>
      <button className={`btn ${small ? 'sm' : ''}`} onClick={() => void show()} disabled={items.length === 0}>
        <FolderPlus size={small ? 13 : 15} /> {t('cases.addToCase')}
      </button>
      {open && (
        <div className="overlay" onClick={() => setOpen(false)}>
          <div className="dialog" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: 10 }}>
              <h3 style={{ flex: 1 }}>{t('cases.addToCase')}</h3>
              <button className="icon-btn" aria-label={t('common.close')} onClick={() => setOpen(false)}><X size={16} /></button>
            </div>
            <div className="small dim" style={{ marginBottom: 10 }}>
              {items.slice(0, 3).map((i) => <div key={i.value}><Ltr mono breakAll>{i.value}</Ltr></div>)}
            </div>
            <div className="small muted" style={{ marginBottom: 6 }}>{t('cases.pickCase')}</div>
            <div className="col" style={{ gap: 6, maxHeight: 220, overflow: 'auto' }}>
              {cases === null ? null : cases.length === 0 ? (
                <div className="small dim">{t('cases.noOpenCases')}</div>
              ) : (
                cases.map((c) => (
                  <button key={c.id} className="btn" style={{ justifyContent: 'flex-start' }} disabled={busy} onClick={() => void addTo(c.id)}>
                    <Ltr mono>{c.id}</Ltr> — {c.name}
                  </button>
                ))
              )}
            </div>
            <div className="small muted" style={{ margin: '14px 0 6px' }}>{t('cases.orNew')}</div>
            <div className="row">
              <input className="input" value={newName} placeholder={t('cases.name')} onChange={(e) => setNewName(e.target.value)} />
              <button className="btn primary" disabled={!newName.trim() || busy} onClick={() => void createAndAdd()}>{t('cases.create')}</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
