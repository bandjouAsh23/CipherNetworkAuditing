import { Download, Laptop, Lock, MonitorDown, Package, ShieldCheck, Terminal } from 'lucide-react';
import { usePWAInstall } from '../hooks/usePWAInstall';
import {
  generatePythonPcAgent,
  generateUnixShellLauncher,
  generateWindowsBatchLauncher,
} from '../utils/pcAgentGenerator';
import { enforceHttpsUrl } from '../utils/targetValidation';

function downloadTextFile(filename: string, content: string, mimeType = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function DesktopAppView({ onOpenImport }: { onOpenImport: () => void }) {
  const { isInstallable, isInstalled, install } = usePWAInstall();
  const rawOrigin = typeof window !== 'undefined' ? window.location.origin : 'https://localhost:3000';
  const appUrl = enforceHttpsUrl(rawOrigin);

  return (
    <div className="space-y-6">
      {/* Standalone PC Executable Download Banner */}
      <section className="bg-[#111827] border border-cyan-500/40 rounded-xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <span className="inline-flex items-center gap-1.5 text-cyan-300 font-medium">
                <Package className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span>Exécutable PC autonome (Windows, macOS, Linux)</span>
              </span>
              <span className="inline-flex items-center gap-1 text-emerald-300 font-medium">
                <Lock className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Exécution locale HTTPS / Loopback 127.0.0.1</span>
              </span>
            </div>
            <h2 className="text-xl font-display font-semibold text-slate-100">
              Exécuter CipherNetworkAuditing directement depuis votre PC
            </h2>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
              Téléchargez l’exécutable autonome tout-en-un : il embarque l’interface 3D complète, le moteur d’analyse des vulnérabilités et le sondeur réseau LAN pour lancer l’outil hors ligne directement sur votre poste et auditer vos cibles autorisées.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <a
            href="/api/download-pc-executable?format=pyzw"
            download="CipherNetworkAuditing.pyzw"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors whitespace-nowrap"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            <span>Exécutable Windows (.pyzw)</span>
          </a>

          <a
            href="/api/download-pc-executable?format=pyz"
            download="CipherNetworkAuditing.pyz"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/40 transition-colors whitespace-nowrap"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            <span>Exécutable Linux / macOS (.pyz)</span>
          </a>

          <a
            href="/api/download-pc-bundle"
            download="CipherNetworkAuditing-PC-Portable.zip"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-medium bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-200 border border-emerald-500/40 transition-colors whitespace-nowrap"
          >
            <Package className="w-4 h-4" aria-hidden="true" />
            <span>Pack Portable PC complet (.zip)</span>
          </a>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-1.5">
            <p className="font-semibold text-slate-100">Windows (Double-clic)</p>
            <p className="text-slate-400 leading-relaxed">
              Double-cliquez sur <code className="text-cyan-300">CipherNetworkAuditing.pyzw</code> (ou <code className="text-cyan-300">Lancer_CipherNetworkAuditing.bat</code> dans le ZIP) pour ouvrir l’application 3D locale sans console.
            </p>
          </div>

          <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-1.5">
            <p className="font-semibold text-slate-100">Linux / macOS</p>
            <p className="text-slate-400 leading-relaxed">
              Exécutez <code className="text-cyan-300">chmod +x CipherNetworkAuditing.pyz &amp;&amp; ./CipherNetworkAuditing.pyz</code> pour démarrer le serveur local et la fenêtre bureau.
            </p>
          </div>

          <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-4 space-y-1.5">
            <p className="font-semibold text-slate-100">Installeur natif .exe / .AppImage</p>
            <p className="text-slate-400 leading-relaxed">
              Le pack inclut aussi la configuration Electron : exécutez <code className="text-cyan-300">npm run build:desktop &amp;&amp; npx electron-builder</code> pour compiler un installeur <code className="text-slate-200">.exe</code>.
            </p>
          </div>
        </div>
      </section>

      {/* PWA Desktop Installation */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-cyan-300">
              <Laptop className="w-4 h-4 shrink-0" aria-hidden="true" />
              <span>Installation rapide navigateur (PWA Bureau HTTPS)</span>
            </div>
            <h3 className="text-base font-display font-semibold text-slate-100">
              Ouvrir la version web HTTPS dans une fenêtre bureau dédiée
            </h3>
            <p className="text-xs text-slate-400 max-w-2xl">
              Installez l’interface comme application de bureau sans barre de navigateur, avec fonctionnement hors ligne.
            </p>
          </div>

          <div className="shrink-0">
            {isInstalled ? (
              <span className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
                <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                <span>Application installée sur ce poste</span>
              </span>
            ) : isInstallable ? (
              <button
                type="button"
                onClick={() => void install()}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors whitespace-nowrap"
              >
                <MonitorDown className="w-4 h-4" aria-hidden="true" />
                <span>Installer sur ce PC maintenant</span>
              </button>
            ) : (
              <span className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 text-slate-200 border border-slate-700">
                <MonitorDown className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                <span>Menu navigateur → Installer CipherNetworkAuditing</span>
              </span>
            )}
          </div>
        </div>
      </section>

      {/* Downloadable CLI Scanner & Quick Script Launchers */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-cyan-300">
              <Terminal className="w-4 h-4" aria-hidden="true" />
              <span>Mode ligne de commande (CLI &amp; Transfert HTTPS)</span>
            </div>
            <h3 className="text-base font-display font-semibold text-slate-100">
              Scanner réseau local pour PC (
              <code className="font-mono text-cyan-300 text-sm">cipher_audit_pc.py</code>)
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Pour les audits automatisés en terminal : cible une IP ou un sous-réseau autorisé, inspecte les ports (ouvert, fermé, filtré) et TLS, puis transfère le résultat en HTTPS.
            </p>

            <pre className="bg-[#0B1120] border border-slate-800 rounded-lg p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto">
{`python3 cipher_audit_pc.py --target 192.168.1.0/24 --authorized
# Avec transfert chiffré direct en HTTPS :
python3 cipher_audit_pc.py --target 192.168.1.10 --authorized --upload-https-url ${appUrl}`}
            </pre>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() =>
                downloadTextFile('cipher_audit_pc.py', generatePythonPcAgent(), 'text/x-python;charset=utf-8')
              }
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Télécharger cipher_audit_pc.py</span>
            </button>

            <button
              type="button"
              onClick={onOpenImport}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap"
            >
              <span>Importer le JSON généré</span>
            </button>
          </div>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-emerald-300">
              <Laptop className="w-4 h-4" aria-hidden="true" />
              <span>Raccourcis Bureau Directs HTTPS</span>
            </div>
            <h3 className="text-base font-display font-semibold text-slate-100">
              Lanceurs directs Windows &amp; Linux / macOS
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Ouvrez <strong>CipherNetworkAuditing</strong> en mode fenêtre applicative autonome (<code className="text-slate-200">--app</code>) sur votre poste via HTTPS.
            </p>
            <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-3 text-xs text-slate-300 space-y-1">
              <p>
                <span className="font-mono text-cyan-300">Windows</span> : double-cliquez sur{' '}
                <code className="text-slate-100">Lancer_CipherNetworkAuditing.bat</code>
              </p>
              <p>
                <span className="font-mono text-cyan-300">Linux / macOS</span> :{' '}
                <code className="text-slate-100">chmod +x lancer_ciphernetwork.sh &amp;&amp; ./lancer_ciphernetwork.sh</code>
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() =>
                downloadTextFile(
                  'Lancer_CipherNetworkAuditing.bat',
                  generateWindowsBatchLauncher(appUrl)
                )
              }
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
              <span>Lanceur Windows (.bat)</span>
            </button>

            <button
              type="button"
              onClick={() =>
                downloadTextFile('lancer_ciphernetwork.sh', generateUnixShellLauncher(appUrl))
              }
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
              <span>Lanceur Linux / macOS (.sh)</span>
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
