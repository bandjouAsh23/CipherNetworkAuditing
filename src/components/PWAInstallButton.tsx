import { useState } from 'react';
import { Download, MonitorDown, WifiOff } from 'lucide-react';
import { useOnlineStatus } from '../hooks/useOnlineStatus';
import { usePWAInstall } from '../hooks/usePWAInstall';

export function PWAInstallButton({ onOpenDesktopGuide }: { onOpenDesktopGuide?: () => void }) {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);

  if (isInstalled) {
    return null;
  }

  if (isInstallable) {
    return (
      <button
        type="button"
        onClick={() => void install()}
        className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 transition-colors whitespace-nowrap"
      >
        <Download className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Installer sur ce PC</span>
      </button>
    );
  }

  if (isIOS) {
    return (
      <>
        <button
          type="button"
          onClick={() => setShowIOSGuide(true)}
          className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-[#0B1120] hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
        >
          <MonitorDown className="w-3.5 h-3.5 text-cyan-400 shrink-0" aria-hidden="true" />
          <span>Installer l’application</span>
        </button>

        {showIOSGuide && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            role="dialog"
            aria-modal="true"
            aria-labelledby="ios-install-title"
          >
            <div className="w-full max-w-sm rounded-xl bg-[#111827] border border-slate-700 p-5">
              <h3 id="ios-install-title" className="text-base font-display font-semibold text-slate-100">
                Installer CipherNetworkAuditing
              </h3>
              <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                1. Touchez le bouton <strong>Partager</strong> dans Safari.
                <br />
                2. Sélectionnez <strong>Sur l’écran d’accueil</strong>.
              </p>
              <button
                type="button"
                onClick={() => setShowIOSGuide(false)}
                className="mt-4 w-full rounded-lg bg-slate-800 hover:bg-slate-700 py-2 text-xs font-medium text-slate-100"
              >
                Fermer
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  if (onOpenDesktopGuide) {
    return (
      <button
        type="button"
        onClick={onOpenDesktopGuide}
        className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-[#0B1120] hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
      >
        <MonitorDown className="w-3.5 h-3.5 text-cyan-400 shrink-0" aria-hidden="true" />
        <span>Lancer sur PC (App)</span>
      </button>
    );
  }

  return null;
}

export function OfflineIndicator() {
  const isOnline = useOnlineStatus();
  if (isOnline) return null;

  return (
    <div
      role="status"
      className="fixed bottom-4 left-4 z-50 flex items-center gap-2 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-slate-950 shadow-lg"
    >
      <WifiOff className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>Mode hors ligne — Données en cache actives</span>
    </div>
  );
}
