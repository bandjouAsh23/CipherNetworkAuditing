import { useMemo, useState } from 'react';
import { AlertTriangle, Search } from 'lucide-react';
import type { NetworkAuditResult, PortState, Protocol } from '../types/network';
import { PortStateBadge } from './SeverityBadge';

interface PortsServicesViewProps {
  audit: NetworkAuditResult;
  initialDeviceFilter: string | 'all';
  onInspectVulnerability: (deviceId: string) => void;
}

export function PortsServicesView({
  audit,
  initialDeviceFilter,
  onInspectVulnerability,
}: PortsServicesViewProps) {
  const [stateFilter, setStateFilter] = useState<'all' | PortState>('all');
  const [protocolFilter, setProtocolFilter] = useState<'all' | Protocol>('all');
  const [deviceFilter, setDeviceFilter] = useState<string>(initialDeviceFilter);
  const [searchQuery, setSearchQuery] = useState('');

  const allRows = useMemo(() => {
    return audit.devices.flatMap((device) =>
      device.ports.map((port) => {
        const relatedFindings = audit.findings.filter(
          (f) => f.deviceId === device.id && f.port === port.port && f.protocol === port.protocol
        );
        return {
          device,
          port,
          relatedFindings,
        };
      })
    );
  }, [audit.devices, audit.findings]);

  const filteredRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allRows.filter(({ device, port }) => {
      if (stateFilter !== 'all' && port.state !== stateFilter) return false;
      if (protocolFilter !== 'all' && port.protocol !== protocolFilter) return false;
      if (deviceFilter !== 'all' && device.id !== deviceFilter) return false;
      if (!q) return true;
      return (
        String(port.port).includes(q) ||
        port.service.toLowerCase().includes(q) ||
        (port.product ?? '').toLowerCase().includes(q) ||
        (port.banner ?? '').toLowerCase().includes(q) ||
        device.ip.toLowerCase().includes(q) ||
        device.hostname.toLowerCase().includes(q)
      );
    });
  }, [allRows, deviceFilter, protocolFilter, searchQuery, stateFilter]);

  return (
    <div className="space-y-6">
      {/* Port distribution summary */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4" aria-label="Répartition des états de ports">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400">Ports ouverts</p>
            <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-emerald-400">
              {audit.summary.openPorts}
            </p>
          </div>
          <PortStateBadge state="open" />
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400">Ports filtrés (pare-feu)</p>
            <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-amber-400">
              {audit.summary.filteredPorts}
            </p>
          </div>
          <PortStateBadge state="filtered" />
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400">Ports fermés</p>
            <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-slate-300">
              {audit.summary.closedPorts}
            </p>
          </div>
          <PortStateBadge state="closed" />
        </div>
      </section>

      {/* Filter & Matrix Table */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 space-y-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Matrice des ports et services associés</h2>
            <p className="text-xs text-slate-400">
              Inspection des états (ouvert, fermé, filtré), bannières et versions détectées
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="relative">
              <Search
                className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                aria-hidden="true"
              />
              <label htmlFor="port-search" className="sr-only">
                Rechercher un port ou service
              </label>
              <input
                id="port-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Port, service, bannière..."
                className="pl-8 pr-3 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-48"
              />
            </div>

            <label htmlFor="port-device-select" className="sr-only">
              Filtrer par appareil
            </label>
            <select
              id="port-device-select"
              value={deviceFilter}
              onChange={(e) => setDeviceFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">Tous les appareils ({audit.devices.length})</option>
              {audit.devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.ip} — {d.hostname}
                </option>
              ))}
            </select>

            <label htmlFor="port-proto-select" className="sr-only">
              Filtrer par protocole
            </label>
            <select
              id="port-proto-select"
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value as 'all' | Protocol)}
              className="px-2.5 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">TCP &amp; UDP</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>

            <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
              {(
                [
                  { id: 'all', label: 'Tous' },
                  { id: 'open', label: 'Ouverts' },
                  { id: 'filtered', label: 'Filtrés' },
                  { id: 'closed', label: 'Fermés' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setStateFilter(tab.id)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    stateFilter === tab.id
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
                <th className="py-3 px-4">Port / Proto</th>
                <th className="py-3 px-4">État</th>
                <th className="py-3 px-4">Service</th>
                <th className="py-3 px-4">Version / Bannière</th>
                <th className="py-3 px-4">Appareil cible</th>
                <th className="py-3 px-4">Sécurité</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-sm">
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-sm text-slate-400">
                    Aucun port ne correspond aux critères sélectionnés.
                  </td>
                </tr>
              ) : (
                filteredRows.map(({ device, port, relatedFindings }) => (
                  <tr
                    key={`${device.id}-${port.port}-${port.protocol}`}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-4 font-mono text-xs font-semibold text-cyan-300 tabular-nums whitespace-nowrap">
                      {port.port}/{port.protocol}
                    </td>
                    <td className="py-3 px-4">
                      <PortStateBadge state={port.state} />
                    </td>
                    <td className="py-3 px-4 text-xs font-medium text-slate-100">{port.service}</td>
                    <td className="py-3 px-4 text-xs">
                      <div className="text-slate-200">
                        {[port.product, port.version].filter(Boolean).join(' ') || '—'}
                      </div>
                      {(port.banner || port.configNotes) && (
                        <div className="font-mono text-[11px] text-slate-400 mt-0.5 truncate max-w-xs">
                          {port.configNotes ?? port.banner}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs">
                      <div className="text-slate-200 font-medium">{device.hostname}</div>
                      <div className="font-mono text-slate-400">{device.ip}</div>
                    </td>
                    <td className="py-3 px-4 text-xs">
                      {relatedFindings.length > 0 ? (
                        <button
                          type="button"
                          onClick={() => onInspectVulnerability(device.id)}
                          className="inline-flex items-center gap-1.5 text-amber-300 hover:text-amber-200 font-medium whitespace-nowrap"
                        >
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                          <span>{relatedFindings.length} anomalie(s)</span>
                        </button>
                      ) : port.state === 'open' ? (
                        <span className="text-emerald-400">Conforme</span>
                      ) : (
                        <span className="text-slate-500">Non exposé</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
