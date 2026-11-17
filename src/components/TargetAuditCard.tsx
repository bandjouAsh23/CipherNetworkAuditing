import { useState, type FormEvent } from 'react';
import { Copy, Crosshair, Download, FileUp, Lock, ShieldCheck, Terminal } from 'lucide-react';
import { generatePythonPcAgent } from '../utils/pcAgentGenerator';
import { enforceHttpsUrl } from '../utils/targetValidation';

export interface TargetScanNotice {
  type: 'error' | 'unreachable';
  message: string;
  localCommand?: string;
}

interface TargetAuditCardProps {
  isScanning: boolean;
  onScanTarget: (target: string, authorized: boolean) => Promise<TargetScanNotice | null>;
  onOpenImport: () => void;
}

function downloadPythonAgent() {
  const blob = new Blob([generatePythonPcAgent()], { type: 'text/x-python;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'cipher_audit_pc.py';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function TargetAuditCard({
  isScanning,
  onScanTarget,
  onOpenImport,
}: TargetAuditCardProps) {
  const [targetInput, setTargetInput] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<TargetScanNotice | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const httpsOrigin =
    typeof window !== 'undefined' ? enforceHttpsUrl(window.location.origin) : 'https://localhost:3000';

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) {
      setNotice({
        type: 'error',
        message: 'Veuillez saisir une adresse IPv4 ou un sous-réseau CIDR cible (ex. 127.0.0.1 ou 192.168.1.0/24).',
      });
      return;
    }
    if (!isAuthorized) {
      setNotice({
        type: 'error',
        message: 'Cochez la confirmation d’autorisation explicite avant de lancer l’analyse cible.',
      });
      return;
    }

    setNotice(null);
    setSubmitting(true);
    try {
      const resultNotice = await onScanTarget(targetInput.trim(), isAuthorized);
      setNotice(resultNotice);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopyCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedCmd(true);
      window.setTimeout(() => setCopiedCmd(false), 1800);
    } catch {
      // Clipboard optional in restricted contexts
    }
  };

  return (
    <section
      aria-label="Analyse d'une cible réseau autorisée"
      className="bg-[#111827] border border-slate-800 rounded-xl p-4 space-y-3"
    >
      <form onSubmit={handleSubmit} className="flex flex-col lg:flex-row lg:items-center gap-3">
        <div className="flex items-center gap-2 shrink-0">
          <Crosshair className="w-4 h-4 text-cyan-400 shrink-0" aria-hidden="true" />
          <label htmlFor="target-ip-input" className="text-xs font-semibold text-slate-100 whitespace-nowrap">
            Cible IP / CIDR autorisée
          </label>
        </div>

        <div className="flex-1 flex flex-col sm:flex-row sm:items-center gap-3 min-w-0">
          <input
            id="target-ip-input"
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="Saisir l'IP cible ou CIDR (ex. 127.0.0.1, 192.168.1.10, 192.168.1.0/24)"
            className="flex-1 min-w-0 px-3 py-2 text-xs font-mono bg-[#0B1120] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />

          <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none shrink-0">
            <input
              id="target-permission-checkbox"
              type="checkbox"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              className="w-4 h-4 rounded border-slate-600 bg-[#0B1120] text-cyan-500 focus:ring-cyan-500"
            />
            <span>Autorisation confirmée</span>
          </label>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="submit"
            disabled={submitting || isScanning}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 transition-colors whitespace-nowrap"
          >
            <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{submitting ? 'Analyse...' : 'Analyser la cible'}</span>
          </button>
        </div>
      </form>

      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
        <span>
          Saisissez une adresse IPv4 ou plage <code className="text-slate-300">/24–/32</code> avec autorisation écrite pour auditer ses ports, services et vulnérabilités.
        </span>
        <span className="inline-flex items-center gap-1 text-emerald-300 font-medium">
          <Lock className="w-3 h-3" aria-hidden="true" />
          <span>Transfert chiffré HTTPS / TLS</span>
        </span>
      </div>

      {notice && notice.type === 'error' && (
        <div
          role="alert"
          className="px-3.5 py-2.5 rounded-lg bg-red-500/15 border border-red-500/40 text-xs text-red-200"
        >
          {notice.message}
        </div>
      )}

      {notice && notice.type === 'unreachable' && (
        <div className="bg-[#0B1120] border border-amber-500/40 rounded-lg p-3.5 space-y-2.5">
          <div className="flex items-start gap-2.5 text-xs text-amber-200">
            <Terminal className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
            <p className="leading-relaxed">{notice.message}</p>
          </div>

          {notice.localCommand && (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-[#111827] border border-slate-800 rounded-lg px-3 py-2">
              <code className="text-[11px] font-mono text-cyan-300 break-all">
                {`${notice.localCommand} --upload-https-url ${httpsOrigin}`}
              </code>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() =>
                    void handleCopyCommand(`${notice.localCommand} --upload-https-url ${httpsOrigin}`)
                  }
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                >
                  <Copy className="w-3 h-3" aria-hidden="true" />
                  <span>{copiedCmd ? 'Copié' : 'Copier'}</span>
                </button>
                <button
                  type="button"
                  onClick={downloadPythonAgent}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-colors"
                >
                  <Download className="w-3 h-3" aria-hidden="true" />
                  <span>Agent .py</span>
                </button>
                <button
                  type="button"
                  onClick={onOpenImport}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                >
                  <FileUp className="w-3 h-3" aria-hidden="true" />
                  <span>Importer JSON</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
