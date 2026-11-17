import { useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, Search, ShieldCheck, Wrench } from 'lucide-react';
import type { FindingCategory, NetworkAuditResult, Severity } from '../types/network';
import { SeverityBadge } from './SeverityBadge';

interface VulnerabilitiesViewProps {
  audit: NetworkAuditResult;
  initialDeviceFilter: string | 'all';
}

export function VulnerabilitiesView({ audit, initialDeviceFilter }: VulnerabilitiesViewProps) {
  const [categoryFilter, setCategoryFilter] = useState<'all' | FindingCategory>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const [deviceFilter, setDeviceFilter] = useState<string>(initialDeviceFilter);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(audit.findings[0]?.id ?? null);

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return audit.findings.filter((f) => {
      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (deviceFilter !== 'all' && f.deviceId !== deviceFilter) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.service.toLowerCase().includes(q) ||
        (f.cve ?? '').toLowerCase().includes(q) ||
        f.deviceIp.toLowerCase().includes(q) ||
        f.deviceHostname.toLowerCase().includes(q)
      );
    });
  }, [audit.findings, categoryFilter, deviceFilter, searchQuery, severityFilter]);

  const vulnerableVersionsCount = audit.findings.filter((f) => f.category === 'vulnerable_version').length;
  const misconfigCount = audit.findings.filter((f) => f.category === 'misconfiguration').length;

  return (
    <div className="space-y-6">
      {/* Category summary cards */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Total des anomalies détectées</p>
          <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-slate-100">
            {audit.findings.length}
          </p>
          <p className="mt-1 text-xs text-slate-400">Classées par sévérité CVSS</p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Versions de services vulnérables</p>
          <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-red-400">
            {vulnerableVersionsCount}
          </p>
          <p className="mt-1 text-xs text-slate-400">CVE connues ou versions obsolètes</p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400">Mauvaises configurations</p>
          <p className="mt-1 text-2xl font-display font-semibold tabular-nums text-amber-400">
            {misconfigCount}
          </p>
          <p className="mt-1 text-xs text-slate-400">Protocoles en clair, accès sans auth, TLS faible</p>
        </div>
      </section>

      {/* Filter toolbar */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
            {(
              [
                { id: 'all', label: 'Toutes' },
                { id: 'vulnerable_version', label: 'Versions vulnérables' },
                { id: 'misconfiguration', label: 'Mauvaises configurations' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCategoryFilter(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  categoryFilter === tab.id
                    ? 'bg-cyan-500/20 text-cyan-300'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-slate-800 rounded-lg">
            {(
              [
                { id: 'all', label: 'Toute sévérité' },
                { id: 'critical', label: 'Critique' },
                { id: 'high', label: 'Élevé' },
                { id: 'medium', label: 'Moyen' },
                { id: 'low', label: 'Faible' },
              ] as const
            ).map((sev) => (
              <button
                key={sev.id}
                type="button"
                onClick={() => setSeverityFilter(sev.id)}
                className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  severityFilter === sev.id
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="vuln-device-select" className="sr-only">
            Filtrer par appareil
          </label>
          <select
            id="vuln-device-select"
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">Tous les appareils</option>
            {audit.devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.ip} — {d.hostname}
              </option>
            ))}
          </select>

          <div className="relative">
            <Search
              className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
              aria-hidden="true"
            />
            <label htmlFor="vuln-search" className="sr-only">
              Rechercher une vulnérabilité ou CVE
            </label>
            <input
              id="vuln-search"
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="CVE, service, hôte..."
              className="pl-8 pr-3 py-1.5 text-xs bg-[#0B1120] border border-slate-700 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-48"
            />
          </div>
        </div>
      </section>

      {/* Findings list */}
      <section className="space-y-3" aria-label="Liste des vulnérabilités et mauvaises configurations">
        {filteredFindings.length === 0 ? (
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-10 text-center">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-slate-100">Aucune anomalie correspondante</h3>
            <p className="text-xs text-slate-400 mt-1">
              {audit.findings.length === 0
                ? 'Cet audit n’a révélé aucune vulnérabilité connue ni mauvaise configuration.'
                : 'Ajustez vos filtres pour afficher les autres constats.'}
            </p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            const categoryText =
              finding.category === 'vulnerable_version' ? 'Version vulnérable' : 'Mauvaise configuration';

            return (
              <div
                key={finding.id}
                className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden"
              >
                <button
                  type="button"
                  aria-expanded={isExpanded}
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="w-full text-left p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/30 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span>{categoryText}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-cyan-300">
                        {finding.deviceIp}
                        {finding.port ? `:${finding.port}/${finding.protocol}` : ''}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{finding.deviceHostname}</span>
                      {finding.cve && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="font-mono text-slate-200">{finding.cve}</span>
                        </>
                      )}
                    </div>
                    <h3 className="text-sm sm:text-base font-semibold text-slate-100">{finding.title}</h3>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {finding.cvss !== undefined && (
                      <span className="text-xs font-mono tabular-nums text-slate-300">
                        CVSS {finding.cvss.toFixed(1)}
                      </span>
                    )}
                    <SeverityBadge severity={finding.severity} />
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" aria-hidden="true" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" aria-hidden="true" />
                    )}
                  </div>
                </button>

                {isExpanded && (
                  <div className="px-4 pb-4 pt-2 border-t border-slate-800/80 grid grid-cols-1 lg:grid-cols-2 gap-5 text-xs">
                    <div className="space-y-3">
                      <div>
                        <h4 className="font-medium text-slate-300 mb-1">Analyse technique</h4>
                        <p className="text-slate-300 leading-relaxed">{finding.description}</p>
                      </div>
                      <div>
                        <h4 className="font-medium text-slate-300 mb-1">Impact potentiel</h4>
                        <p className="text-slate-400 leading-relaxed">{finding.riskImpact}</p>
                      </div>
                      {finding.detectedVersion && (
                        <div className="text-slate-400">
                          Version détectée :{' '}
                          <span className="font-mono text-slate-200">{finding.detectedVersion}</span>
                        </div>
                      )}
                    </div>

                    <div className="bg-[#0B1120] border border-slate-800 rounded-lg p-3.5 space-y-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="inline-flex items-center gap-1.5 font-medium text-cyan-300">
                          <Wrench className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Recommandation ({finding.priority})</span>
                        </span>
                      </div>
                      <p className="text-slate-200 font-medium">{finding.recommendation}</p>
                      <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                        {finding.remediationSteps.map((step, i) => (
                          <li key={i} className="leading-relaxed">
                            {step}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </section>
    </div>
  );
}
