import { useMemo, useState } from 'react';
import { ArrowRight, Box, HardDrive, Network, Search } from 'lucide-react';
import type { DeviceType, NetworkAuditResult, NetworkDevice } from '../types/network';
import { getDeviceHighestSeverity } from '../utils/auditEngine';
import { PortStateBadge, SeverityBadge } from './SeverityBadge';
import { Topology3D } from './Topology3D';
import { TopologyMap } from './TopologyMap';

interface DevicesViewProps {
  audit: NetworkAuditResult;
  isScanning: boolean;
  scanProgress: number;
  scanStageLabel: string;
  discoveredCount: number;
  selectedDeviceId: string | null;
  onSelectDevice: (deviceId: string) => void;
  onNavigateToPorts: (deviceId: string) => void;
  onNavigateToFindings: (deviceId: string) => void;
}

const DEVICE_TYPE_LABEL: Record<DeviceType, string> = {
  gateway: 'Passerelle',
  firewall: 'Pare-feu',
  server: 'Serveur',
  database: 'Base de données',
  workstation: 'Poste client',
  iot: 'Équipement IoT',
  printer: 'Imprimante',
  unknown: 'Appareil réseau',
};

export function DevicesView({
  audit,
  isScanning,
  scanProgress,
  scanStageLabel,
  discoveredCount,
  selectedDeviceId,
  onSelectDevice,
  onNavigateToPorts,
  onNavigateToFindings,
}: DevicesViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'critical' | 'high' | 'safe'>('all');
  const [topologyMode, setTopologyMode] = useState<'3d' | '2d'>('3d');

  const visibleDevices = useMemo(() => {
    const base = isScanning ? audit.devices.slice(0, Math.max(1, discoveredCount)) : audit.devices;
    const q = searchQuery.trim().toLowerCase();

    return base.filter((device) => {
      const matchesQuery =
        !q ||
        device.ip.toLowerCase().includes(q) ||
        device.hostname.toLowerCase().includes(q) ||
        (device.os ?? '').toLowerCase().includes(q) ||
        (device.vendor ?? '').toLowerCase().includes(q);

      if (!matchesQuery) return false;
      if (riskFilter === 'all') return true;
      const highest = getDeviceHighestSeverity(device, audit.findings);
      if (riskFilter === 'safe') return highest === 'safe' || highest === 'low';
      return highest === riskFilter;
    });
  }, [audit.devices, audit.findings, discoveredCount, isScanning, riskFilter, searchQuery]);

  const selectedDevice: NetworkDevice | undefined =
    audit.devices.find((d) => d.id === selectedDeviceId) ?? audit.devices[0];

  const selectedDeviceFindings = selectedDevice
    ? audit.findings.filter((f) => f.deviceId === selectedDevice.id)
    : [];

  const scoreTone =
    audit.summary.hardeningScore >= 80
      ? 'text-emerald-400'
      : audit.summary.hardeningScore >= 55
        ? 'text-amber-400'
        : 'text-red-400';

  return (
    <div className="space-y-6">
      {/* Scan progress bar when active */}
      {isScanning && (
        <div
          className="bg-[#111827] border border-cyan-500/40 rounded-xl p-4"
          role="status"
          aria-live="polite"
        >
          <div className="flex items-center justify-between gap-4 mb-2">
            <span className="text-sm font-medium text-cyan-200">{scanStageLabel}</span>
            <span className="text-xs font-mono tabular-nums text-cyan-300">{scanProgress}%</span>
          </div>
          <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden">
            <div
              className="h-full bg-cyan-500 transition-all duration-200"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* 4-column KPI strip */}
      <section aria-label="Indicateurs de l'audit réseau" className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Appareils détectés</p>
          <p className="mt-1.5 text-2xl font-display font-semibold tabular-nums text-slate-100">
            {isScanning ? Math.min(discoveredCount, audit.summary.totalDevices) : audit.summary.totalDevices}
          </p>
          <p className="mt-1 text-xs font-mono text-slate-400 truncate">{audit.subnet}</p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Ports ouverts / filtrés</p>
          <p className="mt-1.5 text-2xl font-display font-semibold tabular-nums text-slate-100">
            {audit.summary.openPorts}{' '}
            <span className="text-sm font-normal text-slate-400">/ {audit.summary.filteredPorts} filtrés</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 tabular-nums">{audit.summary.closedPorts} ports fermés</p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Vulnérabilités &amp; Alertes</p>
          <p className="mt-1.5 text-2xl font-display font-semibold tabular-nums text-slate-100">
            {audit.findings.length}
          </p>
          <p className="mt-1 text-xs text-slate-400 tabular-nums">
            <span className="text-red-400 font-medium">{audit.summary.criticalCount} critiques</span>
            <span aria-hidden="true"> · </span>
            <span className="text-amber-400 font-medium">{audit.summary.highCount} élevées</span>
          </p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Indice de durcissement</p>
          <p className={`mt-1.5 text-2xl font-display font-semibold tabular-nums ${scoreTone}`}>
            {audit.summary.hardeningScore} <span className="text-sm font-normal text-slate-400">/ 100</span>
          </p>
          <p className="mt-1 text-xs text-slate-400">
            Risque global : <span className="text-slate-200 font-medium">{audit.summary.globalRiskLevel}</span>
          </p>
        </div>
      </section>

      {/* Topology + Selected Device Inspector */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-stretch">
        <div className="xl:col-span-7 flex flex-col">
          {topologyMode === '3d' ? (
            <div className="relative bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between flex-1">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 sm:gap-4 mb-3">
                <div>
                  <h2 className="text-base font-semibold text-slate-100">Cartographie 3D du réseau</h2>
                  <p className="text-xs text-slate-400">
                    Glissez pour pivoter, molette pour zoomer, cliquez sur un équipement
                  </p>
                </div>

                <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg shrink-0 self-start sm:self-auto">
                  <button
                    type="button"
                    onClick={() => setTopologyMode('3d')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md bg-cyan-500/20 text-cyan-300 whitespace-nowrap"
                  >
                    <Box className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Vue 3D</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setTopologyMode('2d')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md text-slate-400 hover:text-slate-200 whitespace-nowrap"
                  >
                    <Network className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Vue 2D</span>
                  </button>
                </div>
              </div>

              <Topology3D
                devices={audit.devices}
                findings={audit.findings}
                selectedDeviceId={selectedDevice?.id ?? null}
                onSelectDevice={onSelectDevice}
                isScanning={isScanning}
                discoveredCount={discoveredCount}
              />
            </div>
          ) : (
            <div className="flex flex-col gap-2 flex-1">
              <div className="flex justify-end">
                <div className="flex items-center gap-1 p-1 bg-[#111827] border border-slate-800 rounded-lg">
                  <button
                    type="button"
                    onClick={() => setTopologyMode('3d')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md text-slate-400 hover:text-slate-200 whitespace-nowrap"
                  >
                    <Box className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Vue 3D</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setTopologyMode('2d')}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md bg-cyan-500/20 text-cyan-300 whitespace-nowrap"
                  >
                    <Network className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Vue 2D</span>
                  </button>
                </div>
              </div>
              <TopologyMap
                devices={audit.devices}
                findings={audit.findings}
                selectedDeviceId={selectedDevice?.id ?? null}
                onSelectDevice={onSelectDevice}
                isScanning={isScanning}
                discoveredCount={discoveredCount}
              />
            </div>
          )}
        </div>

        <div className="xl:col-span-5 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          {selectedDevice ? (
            <>
              <div>
                <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-800">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
                      <HardDrive className="w-3.5 h-3.5 text-cyan-400 shrink-0" aria-hidden="true" />
                      <span>{DEVICE_TYPE_LABEL[selectedDevice.deviceType]}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{selectedDevice.ip}</span>
                    </div>
                    <h2 className="text-lg font-display font-semibold text-slate-100 truncate">
                      {selectedDevice.hostname}
                    </h2>
                  </div>
                  <SeverityBadge severity={getDeviceHighestSeverity(selectedDevice, audit.findings)} />
                </div>

                <dl className="grid grid-cols-2 gap-x-4 gap-y-3 py-4 text-xs border-b border-slate-800">
                  <div>
                    <dt className="text-slate-400">Adresse MAC</dt>
                    <dd className="mt-0.5 font-mono text-slate-200">{selectedDevice.mac ?? 'Non détectée'}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Constructeur</dt>
                    <dd className="mt-0.5 text-slate-200 truncate">{selectedDevice.vendor ?? 'Inconnu'}</dd>
                  </div>
                  <div className="col-span-2">
                    <dt className="text-slate-400">Système / Firmware</dt>
                    <dd className="mt-0.5 text-slate-200">{selectedDevice.os ?? 'Empreinte non identifiée'}</dd>
                  </div>
                </dl>

                <div className="py-4">
                  <h3 className="text-xs font-medium text-slate-300 mb-2.5">
                    Ports détectés ({selectedDevice.ports.length})
                  </h3>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {selectedDevice.ports.map((port) => (
                      <div
                        key={`${port.port}-${port.protocol}`}
                        className="flex items-center justify-between gap-3 py-1.5 px-2.5 rounded-lg bg-[#0B1120] border border-slate-800/80 text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-mono font-medium text-cyan-300">
                            {port.port}/{port.protocol}
                          </span>
                          <span className="mx-2 text-slate-600" aria-hidden="true">
                            ·
                          </span>
                          <span className="text-slate-200">{port.service}</span>
                          {port.product && (
                            <span className="ml-1.5 text-slate-400">
                              ({port.product} {port.version ?? ''})
                            </span>
                          )}
                        </div>
                        <PortStateBadge state={port.state} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => onNavigateToPorts(selectedDevice.id)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors whitespace-nowrap"
                >
                  <span>Voir tous les ports</span>
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigateToFindings(selectedDevice.id)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 transition-colors whitespace-nowrap"
                >
                  <span>{selectedDeviceFindings.length} anomalie(s) détectée(s)</span>
                  <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              </div>
            </>
          ) : (
            <p className="text-sm text-slate-400">Aucun appareil sélectionné.</p>
          )}
        </div>
      </section>

      {/* Devices Inventory Table */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Inventaire des appareils connectés</h2>
            <p className="text-xs text-slate-400">
              Identification par adresse IP, nom d’hôte, adresse MAC et niveau d’exposition
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search
                className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                aria-hidden="true"
              />
              <label htmlFor="device-search" className="sr-only">
                Rechercher un appareil par IP ou nom d'hôte
              </label>
              <input
                id="device-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filtrer IP, hôte, OS..."
                className="pl-8 pr-3 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-52"
              />
            </div>

            <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
              {(
                [
                  { id: 'all', label: 'Tous' },
                  { id: 'critical', label: 'Critiques' },
                  { id: 'high', label: 'Élevés' },
                  { id: 'safe', label: 'Sains' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setRiskFilter(tab.id)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    riskFilter === tab.id
                      ? 'bg-cyan-500/20 text-cyan-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-medium text-slate-400 bg-[#0F172A]/60">
                <th className="py-3 px-4">Nom d’hôte</th>
                <th className="py-3 px-4">Adresse IP</th>
                <th className="py-3 px-4">MAC / Constructeur</th>
                <th className="py-3 px-4">Système</th>
                <th className="py-3 px-4 text-right">Ports ouverts</th>
                <th className="py-3 px-4">Risque</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-sm">
              {visibleDevices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-sm text-slate-400">
                    Aucun appareil ne correspond à votre filtre de recherche.
                  </td>
                </tr>
              ) : (
                visibleDevices.map((device) => {
                  const openCount = device.ports.filter((p) => p.state === 'open').length;
                  const filteredCount = device.ports.filter((p) => p.state === 'filtered').length;
                  const highestRisk = getDeviceHighestSeverity(device, audit.findings);
                  const isSelected = selectedDevice?.id === device.id;

                  return (
                    <tr
                      key={device.id}
                      className={`transition-colors ${
                        isSelected ? 'bg-cyan-500/10' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-3 px-4">
                        <button
                          type="button"
                          onClick={() => onSelectDevice(device.id)}
                          className="text-left font-medium text-slate-100 hover:text-cyan-300 transition-colors focus:outline-none focus-visible:underline"
                        >
                          {device.hostname}
                        </button>
                        <div className="text-xs text-slate-400">{DEVICE_TYPE_LABEL[device.deviceType]}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-cyan-300 tabular-nums">{device.ip}</td>
                      <td className="py-3 px-4 text-xs">
                        <div className="font-mono text-slate-300">{device.mac ?? '—'}</div>
                        <div className="text-slate-400">{device.vendor ?? 'Inconnu'}</div>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-300">{device.os ?? 'Non identifié'}</td>
                      <td className="py-3 px-4 text-right font-mono text-xs tabular-nums">
                        <span className="text-emerald-300 font-medium">
                          {openCount} {openCount > 1 ? 'ouverts' : 'ouvert'}
                        </span>
                        {filteredCount > 0 && (
                          <span className="text-amber-300 ml-1.5">
                            · {filteredCount} {filteredCount > 1 ? 'filtrés' : 'filtré'}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={highestRisk} />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
