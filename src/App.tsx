import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  FileText,
  FileUp,
  Laptop,
  Lock,
  Menu,
  Network,
  Play,
  Radar,
  Server,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react';
import { DesktopAppView } from './components/DesktopAppView';
import { DevicesView } from './components/DevicesView';
import { ImportScanModal } from './components/ImportScanModal';
import { PortsServicesView } from './components/PortsServicesView';
import { OfflineIndicator, PWAInstallButton } from './components/PWAInstallButton';
import { ReportView } from './components/ReportView';
import { TargetAuditCard, type TargetScanNotice } from './components/TargetAuditCard';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import { NETWORK_AUDIT_PROFILES } from './data/auditProfiles';
import type { NetworkAuditResult, NetworkDevice } from './types/network';
import { evaluateNetworkAudit } from './utils/auditEngine';
import { parseScanInput } from './utils/nmapParser';

type ActiveView = 'devices' | 'ports' | 'vulnerabilities' | 'report' | 'desktop';

const SCAN_STAGES = [
  { progress: 22, label: 'Découverte des hôtes actifs (ARP / ICMP)...' },
  { progress: 52, label: 'Détection des ports ouverts, fermés et filtrés...' },
  { progress: 78, label: 'Identification des versions de services et bannières...' },
  { progress: 94, label: 'Corrélation CVE et vérification des configurations...' },
];

export default function App() {
  const initialProfile = NETWORK_AUDIT_PROFILES[0];
  const initialAudit = useMemo(
    () =>
      evaluateNetworkAudit({
        id: `init-${initialProfile.id}`,
        profileName: initialProfile.name,
        subnet: initialProfile.subnet,
        sourceType: 'profile',
        devices: initialProfile.devices,
      }),
    [initialProfile]
  );

  const [activeView, setActiveView] = useState<ActiveView>('devices');
  const [selectedProfileId, setSelectedProfileId] = useState<string>(initialProfile.id);
  const [currentAudit, setCurrentAudit] = useState<NetworkAuditResult>(initialAudit);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(
    initialAudit.devices[0]?.id ?? null
  );
  const [portsDeviceFilter, setPortsDeviceFilter] = useState<string>('all');
  const [vulnDeviceFilter, setVulnDeviceFilter] = useState<string>('all');
  const [resolvedFindingIds, setResolvedFindingIds] = useState<Set<string>>(new Set());

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(100);
  const [scanStageLabel, setScanStageLabel] = useState('');
  const [discoveredCount, setDiscoveredCount] = useState(initialAudit.devices.length);

  const [isImportOpen, setIsImportOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const timersRef = useRef<number[]>([]);

  const clearScanTimers = useCallback(() => {
    for (const id of timersRef.current) {
      window.clearTimeout(id);
    }
    timersRef.current = [];
  }, []);

  useEffect(() => {
    return () => clearScanTimers();
  }, [clearScanTimers]);

  const applyAuditWithSweep = useCallback(
    (nextAudit: NetworkAuditResult) => {
      clearScanTimers();
      setApiError(null);
      setCurrentAudit(nextAudit);
      setSelectedDeviceId(nextAudit.devices[0]?.id ?? null);
      setPortsDeviceFilter('all');
      setVulnDeviceFilter('all');
      setResolvedFindingIds(new Set());

      const prefersReducedMotion =
        typeof window !== 'undefined' &&
        window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

      if (prefersReducedMotion) {
        setIsScanning(false);
        setScanProgress(100);
        setDiscoveredCount(nextAudit.devices.length);
        return;
      }

      setIsScanning(true);
      setScanProgress(12);
      setScanStageLabel(SCAN_STAGES[0].label);
      setDiscoveredCount(1);

      SCAN_STAGES.forEach((stage, index) => {
        const delay = (index + 1) * 190;
        const t = window.setTimeout(() => {
          setScanProgress(stage.progress);
          setScanStageLabel(stage.label);
          const ratio = (index + 1) / SCAN_STAGES.length;
          setDiscoveredCount(Math.max(1, Math.ceil(nextAudit.devices.length * ratio)));
        }, delay);
        timersRef.current.push(t);
      });

      const doneTimer = window.setTimeout(() => {
        setIsScanning(false);
        setScanProgress(100);
        setDiscoveredCount(nextAudit.devices.length);
      }, 920);
      timersRef.current.push(doneTimer);
    },
    [clearScanTimers]
  );

  const handleSelectProfile = (profileId: string) => {
    setSelectedProfileId(profileId);
    setMobileMenuOpen(false);
    const profile = NETWORK_AUDIT_PROFILES.find((p) => p.id === profileId);
    if (!profile) return;

    const evaluated = evaluateNetworkAudit({
      id: `audit-${profile.id}-${Date.now()}`,
      profileName: profile.name,
      subnet: profile.subnet,
      sourceType: 'profile',
      devices: profile.devices,
    });
    applyAuditWithSweep(evaluated);
  };

  const handleRunLocalHostAudit = async () => {
    setMobileMenuOpen(false);
    setSelectedProfileId('local-host');
    setApiError(null);
    setIsScanning(true);
    setScanProgress(30);
    setScanStageLabel("Inspection des interfaces réseau et ports locaux de l'hôte...");

    try {
      const response = await fetch('/api/local-host');
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Impossible d'inspecter l'hôte local.");
      }
      const auditResult: NetworkAuditResult = data.needsClientEval
        ? evaluateNetworkAudit({
            id: data.id ?? `local-${Date.now()}`,
            profileName: data.profileName ?? 'Poste PC Local',
            subnet: data.subnet ?? '127.0.0.0/8',
            sourceType: 'local_host',
            devices: (data.devices ?? []) as NetworkDevice[],
            durationMs: data.durationMs,
          })
        : (data as NetworkAuditResult);
      applyAuditWithSweep(auditResult);
    } catch (err) {
      setIsScanning(false);
      setApiError(
        err instanceof Error ? err.message : "Erreur lors de la communication avec l'API locale."
      );
    }
  };

  const handleRelaunchAudit = () => {
    if (selectedProfileId === 'local-host') {
      void handleRunLocalHostAudit();
      return;
    }
    const profile = NETWORK_AUDIT_PROFILES.find((p) => p.id === selectedProfileId);
    if (profile) {
      handleSelectProfile(profile.id);
    } else {
      const reEvaluated = evaluateNetworkAudit({
        id: `reaudit-${Date.now()}`,
        profileName: currentAudit.profileName,
        subnet: currentAudit.subnet,
        sourceType: currentAudit.sourceType,
        devices: currentAudit.devices,
      });
      applyAuditWithSweep(reEvaluated);
    }
  };

  const handleImportScanSubmit = async (rawInput: string, profileName: string) => {
    const response = await fetch('/api/analyze-nmap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawInput, profileName }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Échec de l'analyse du scan importé.");
    }
    const auditResult: NetworkAuditResult = data.needsClientParse
      ? (() => {
          const parsed = parseScanInput(data.rawInput ?? rawInput);
          return evaluateNetworkAudit({
            id: `import-${Date.now()}`,
            profileName: data.profileName ?? profileName,
            subnet: parsed.subnetLabel,
            sourceType: 'nmap_import',
            devices: parsed.devices,
          });
        })()
      : (data as NetworkAuditResult);
    setSelectedProfileId('nmap-import');
    setActiveView('devices');
    applyAuditWithSweep(auditResult);
  };

  const handleScanTarget = async (
    target: string,
    authorized: boolean
  ): Promise<TargetScanNotice | null> => {
    setApiError(null);
    try {
      const response = await fetch('/api/scan-target', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, authorized }),
      });
      const data = await response.json();

      if (!response.ok) {
        if (data.localCommand) {
          return {
            type: 'unreachable',
            message: data.error || 'Analyse directe non autorisée depuis le cloud.',
            localCommand: data.localCommand,
          };
        }
        return {
          type: 'error',
          message: data.error || "Impossible d'analyser la cible demandée.",
        };
      }

      if (!data.reachable) {
        return {
          type: 'unreachable',
          message:
            data.message ||
            'Cible privée non joignable depuis cet environnement cloud. Lancez l’agent local PC.',
          localCommand: data.localCommand,
        };
      }

      const auditResult: NetworkAuditResult = data.needsClientEval
        ? evaluateNetworkAudit({
            id: data.id ?? `target-${Date.now()}`,
            profileName: data.profileName ?? `Cible autorisée (${target})`,
            subnet: data.subnet ?? target,
            sourceType: 'target_scan',
            devices: (data.devices ?? []) as NetworkDevice[],
            durationMs: data.durationMs,
          })
        : (data.audit as NetworkAuditResult);

      setSelectedProfileId('target-scan');
      setActiveView('devices');
      applyAuditWithSweep(auditResult);
      return null;
    } catch (err) {
      return {
        type: 'error',
        message:
          err instanceof Error ? err.message : "Erreur de connexion sécurisée lors de l'analyse cible.",
      };
    }
  };

  const handleToggleResolved = (findingId: string) => {
    setResolvedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const navItems: Array<{
    id: ActiveView;
    label: string;
    icon: typeof Network;
    count?: number;
  }> = [
    {
      id: 'devices',
      label: 'Appareils & Topologie',
      icon: Network,
      count: currentAudit.summary.totalDevices,
    },
    {
      id: 'ports',
      label: 'Ports & Services',
      icon: Activity,
      count: currentAudit.summary.openPorts,
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnérabilités',
      icon: ShieldAlert,
      count: currentAudit.findings.length,
    },
    {
      id: 'report',
      label: 'Rapport de Sécurité',
      icon: FileText,
    },
    {
      id: 'desktop',
      label: 'Application PC',
      icon: Laptop,
    },
  ];

  const viewTitleMap: Record<ActiveView, string> = {
    devices: 'Appareils & Topologie 3D',
    ports: 'Ports & Services',
    vulnerabilities: 'Vulnérabilités & Configurations',
    report: 'Rapport de Sécurité',
    desktop: 'Application PC & Agent Local',
  };

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex">
      {/* Mobile Sidebar Backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 w-64 shrink-0 bg-[#0F172A] border-r border-slate-800 flex flex-col justify-between transition-transform duration-200 lg:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="p-5 space-y-6 overflow-y-auto">
          {/* Brand Wordmark */}
          <div className="flex items-center justify-between gap-2">
            <a
              href="#top"
              onClick={(e) => {
                e.preventDefault();
                setActiveView('devices');
              }}
              className="inline-flex items-center gap-2 text-sm font-display font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
            >
              <Shield className="w-5 h-5 text-cyan-400 shrink-0" aria-hidden="true" />
              <span>CipherNetworkAuditing</span>
            </a>

            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              aria-label="Fermer le menu de navigation"
              className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-slate-100"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>

          {/* Primary Navigation */}
          <nav aria-label="Navigation principale" className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    if (item.id === 'ports') setPortsDeviceFilter('all');
                    if (item.id === 'vulnerabilities') setVulnDeviceFilter('all');
                    setActiveView(item.id);
                    setMobileMenuOpen(false);
                  }}
                  aria-current={isActive ? 'page' : undefined}
                  className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <span className="inline-flex items-center gap-2.5 min-w-0">
                    <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span className="truncate">{item.label}</span>
                  </span>
                  {item.count !== undefined && (
                    <span className="font-mono text-[11px] tabular-nums text-slate-400">
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Audit Scope / Environment Selector */}
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <p className="px-1 text-xs font-medium text-slate-400">Périmètre d’audit</p>

            <div className="space-y-1">
              {NETWORK_AUDIT_PROFILES.map((profile) => {
                const isSelected = selectedProfileId === profile.id;
                return (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => handleSelectProfile(profile.id)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-colors ${
                      isSelected
                        ? 'bg-slate-800 text-slate-100 border border-slate-700'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                    }`}
                  >
                    <div className="font-medium truncate">{profile.name}</div>
                    <div className="font-mono text-[11px] text-slate-500 mt-0.5">{profile.subnet}</div>
                  </button>
                );
              })}

              <button
                type="button"
                onClick={handleRunLocalHostAudit}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-colors flex items-center gap-2 ${
                  selectedProfileId === 'local-host'
                    ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Server className="w-3.5 h-3.5 shrink-0 text-cyan-400" aria-hidden="true" />
                <div className="min-w-0">
                  <div className="font-medium truncate">Hôte local (Système)</div>
                  <div className="text-[11px] text-slate-500">Interfaces &amp; ports actifs</div>
                </div>
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar Footer Actions */}
        <div className="p-4 border-t border-slate-800 space-y-2">
          <PWAInstallButton
            onOpenDesktopGuide={() => {
              setActiveView('desktop');
              setMobileMenuOpen(false);
            }}
          />
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              setIsImportOpen(true);
            }}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-[#0B1120] hover:bg-slate-800 text-slate-200 border border-slate-700 transition-colors whitespace-nowrap"
          >
            <FileUp className="w-3.5 h-3.5 text-cyan-400 shrink-0" aria-hidden="true" />
            <span>Importer Nmap XML / JSON</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Bar Contract: Breadcrumb on left + 1-2 Actions on right */}
        <header className="sticky top-0 z-20 bg-[#0B1120]/95 backdrop-blur border-b border-slate-800 px-4 sm:px-6 py-3.5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Ouvrir le menu"
              className="lg:hidden p-2 rounded-lg text-slate-300 hover:bg-slate-800"
            >
              <Menu className="w-4 h-4" aria-hidden="true" />
            </button>

            <div className="flex items-center gap-2 text-xs sm:text-sm min-w-0">
              <span className="text-slate-400 whitespace-nowrap hidden sm:inline">
                {currentAudit.profileName}
              </span>
              <span className="text-slate-600 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <h1 className="font-display font-semibold text-slate-100 truncate">
                {viewTitleMap[activeView]}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <span
              title="Transfert chiffré TLS / HTTPS"
              className="hidden md:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 whitespace-nowrap"
            >
              <Lock className="w-3 h-3" aria-hidden="true" />
              <span>HTTPS</span>
            </span>

            <button
              type="button"
              onClick={() => setIsImportOpen(true)}
              className="hidden sm:inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <FileUp className="w-3.5 h-3.5 text-cyan-400" aria-hidden="true" />
              <span>Importer un scan</span>
            </button>

            <button
              type="button"
              onClick={handleRelaunchAudit}
              disabled={isScanning}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              {isScanning ? (
                <>
                  <Radar className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                  <span>Analyse en cours...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Lancer l’audit</span>
                </>
              )}
            </button>
          </div>
        </header>

        {/* Main Viewport */}
        <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto space-y-6">
          {apiError && (
            <div
              role="alert"
              className="flex items-center justify-between gap-4 px-4 py-3 rounded-xl bg-red-500/15 border border-red-500/40 text-xs text-red-200"
            >
              <span>{apiError}</span>
              <button
                type="button"
                onClick={() => setApiError(null)}
                aria-label="Fermer le message d'erreur"
                className="text-red-200 hover:text-white"
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>
          )}

          {activeView === 'devices' && (
            <>
              <TargetAuditCard
                isScanning={isScanning}
                onScanTarget={handleScanTarget}
                onOpenImport={() => setIsImportOpen(true)}
              />
              <DevicesView
                audit={currentAudit}
                isScanning={isScanning}
                scanProgress={scanProgress}
                scanStageLabel={scanStageLabel}
                discoveredCount={discoveredCount}
                selectedDeviceId={selectedDeviceId}
                onSelectDevice={(id) => setSelectedDeviceId(id)}
                onNavigateToPorts={(deviceId) => {
                  setPortsDeviceFilter(deviceId);
                  setActiveView('ports');
                }}
                onNavigateToFindings={(deviceId) => {
                  setVulnDeviceFilter(deviceId);
                  setActiveView('vulnerabilities');
                }}
              />
            </>
          )}

          {activeView === 'ports' && (
            <PortsServicesView
              key={`ports-${currentAudit.id}-${portsDeviceFilter}`}
              audit={currentAudit}
              initialDeviceFilter={portsDeviceFilter}
              onInspectVulnerability={(deviceId) => {
                setVulnDeviceFilter(deviceId);
                setActiveView('vulnerabilities');
              }}
            />
          )}

          {activeView === 'vulnerabilities' && (
            <VulnerabilitiesView
              key={`vuln-${currentAudit.id}-${vulnDeviceFilter}`}
              audit={currentAudit}
              initialDeviceFilter={vulnDeviceFilter}
            />
          )}

          {activeView === 'report' && (
            <ReportView
              audit={currentAudit}
              resolvedFindingIds={resolvedFindingIds}
              onToggleResolved={handleToggleResolved}
            />
          )}

          {activeView === 'desktop' && (
            <DesktopAppView onOpenImport={() => setIsImportOpen(true)} />
          )}
        </main>
      </div>

      <ImportScanModal
        isOpen={isImportOpen}
        onClose={() => setIsImportOpen(false)}
        onSubmitScan={handleImportScanSubmit}
      />

      <OfflineIndicator />
    </div>
  );
}
