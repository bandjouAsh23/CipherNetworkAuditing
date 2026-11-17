import { useState, type ChangeEvent, type FormEvent } from 'react';
import { FileUp, Upload, X } from 'lucide-react';
import { SAMPLE_NMAP_XML } from '../data/auditProfiles';

interface ImportScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmitScan: (rawInput: string, profileName: string) => Promise<void>;
}

export function ImportScanModal({ isOpen, onClose, onSubmitScan }: ImportScanModalProps) {
  const [profileName, setProfileName] = useState('Audit Nmap Importé');
  const [rawInput, setRawInput] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErrorMsg(null);
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setRawInput(reader.result);
        const baseName = file.name.replace(/\.(xml|json)$/i, '');
        if (baseName) setProfileName(`Import — ${baseName}`);
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!rawInput.trim()) {
      setErrorMsg('Veuillez coller un export Nmap XML / JSON ou charger un fichier.');
      return;
    }
    setErrorMsg(null);
    setSubmitting(true);
    try {
      await onSubmitScan(rawInput, profileName.trim() || 'Scan Nmap Importé');
      onClose();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Erreur lors de l’analyse du fichier.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-modal-title"
    >
      <div className="w-full max-w-2xl bg-[#111827] border border-slate-700 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <FileUp className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 id="import-modal-title" className="text-base font-display font-semibold text-slate-100">
              Importer un scan réseau (Nmap XML / JSON)
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fermer la fenêtre d'import"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label htmlFor="import-profile-name" className="block text-xs font-medium text-slate-300 mb-1.5">
                Nom de l’audit
              </label>
              <input
                id="import-profile-name"
                type="text"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label htmlFor="import-file-upload" className="block text-xs font-medium text-slate-300 mb-1.5">
                Charger un fichier (.xml ou .json)
              </label>
              <label
                htmlFor="import-file-upload"
                className="flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium bg-[#0B1120] border border-dashed border-slate-700 hover:border-cyan-500 rounded-lg text-slate-300 cursor-pointer transition-colors"
              >
                <Upload className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
                <span>Sélectionner un fichier</span>
                <input
                  id="import-file-upload"
                  type="file"
                  accept=".xml,.json,text/xml,application/json"
                  onChange={handleFileChange}
                  className="sr-only"
                />
              </label>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between gap-2 mb-1.5">
              <label htmlFor="import-raw-content" className="text-xs font-medium text-slate-300">
                Contenu Nmap XML (<code className="text-cyan-300">nmap -sV -oX scan.xml</code>) ou JSON
              </label>
              <button
                type="button"
                onClick={() => {
                  setRawInput(SAMPLE_NMAP_XML);
                  setProfileName('Lab Agence — Import Nmap');
                  setErrorMsg(null);
                }}
                className="text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Charger un exemple Nmap XML
              </button>
            </div>
            <textarea
              id="import-raw-content"
              rows={9}
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              placeholder="<nmaprun>...</nmaprun> ou { &quot;devices&quot;: [...] }"
              className="w-full px-3 py-2 text-xs font-mono bg-[#0B1120] border border-slate-700 rounded-lg text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="px-3 py-2 rounded-lg bg-red-500/15 border border-red-500/40 text-xs text-red-200"
            >
              {errorMsg}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium rounded-lg text-slate-300 hover:text-slate-100 hover:bg-slate-800 transition-colors"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60 text-slate-950 transition-colors"
            >
              {submitting ? 'Analyse en cours...' : 'Analyser le scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
