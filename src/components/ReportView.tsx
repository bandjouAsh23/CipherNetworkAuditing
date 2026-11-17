import { FileJson, FileText, Printer, ShieldCheck } from 'lucide-react';
import type { NetworkAuditResult, RemediationPriority } from '../types/network';
import {
  calculateProjectedScore,
  generateJsonReport,
  generateMarkdownReport,
} from '../utils/reportGenerator';
import { SeverityBadge } from './SeverityBadge';

interface ReportViewProps {
  audit: NetworkAuditResult;
  resolvedFindingIds: Set<string>;
  onToggleResolved: (findingId: string) => void;
}

const PRIORITY_SECTION: Array<{
  priority: RemediationPriority;
  title: string;
  subtitle: string;
}> = [
  {
    priority: 'P1',
    title: 'Priorité 1 — Actions immédiates',
    subtitle: 'Vulnérabilités critiques ou services en clair exposés sur le réseau',
  },
  {
    priority: 'P2',
    title: 'Priorité 2 — Correctifs à court terme',
    subtitle: 'Mises à jour de versions et durcissement des protocoles TLS / SSH',
  },
  {
    priority: 'P3',
    title: 'Priorité 3 — Durcissement continu',
    subtitle: 'Segmentation VLAN et réduction de surface d’attaque interne',
  },
];

function triggerDownload(filename: string, content: string, mimeType: string) {
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

export function ReportView({ audit, resolvedFindingIds, onToggleResolved }: ReportViewProps) {
  const projection = calculateProjectedScore(audit, resolvedFindingIds);
  const formattedDate = new Date(audit.scannedAt).toLocaleString('fr-FR', {
    dateStyle: 'long',
    timeStyle: 'short',
  });

  const slugName = audit.profileName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

  const handleExportMarkdown = () => {
    const md = generateMarkdownReport(audit, resolvedFindingIds);
    triggerDownload(`rapport-securite-${slugName || 'reseau'}.md`, md, 'text/markdown;charset=utf-8');
  };

  const handleExportJson = () => {
    const json = generateJsonReport(audit, resolvedFindingIds);
    triggerDownload(`rapport-securite-${slugName || 'reseau'}.json`, json, 'application/json;charset=utf-8');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Executive Header & Export Actions */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl p-6 print-surface">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div>
            <div className="text-xs text-slate-400 flex flex-wrap items-center gap-2 mb-1">
              <span>Rapport d’Audit de Sécurité</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono text-cyan-300">{audit.subnet}</span>
              <span aria-hidden="true">·</span>
              <span>{formattedDate}</span>
            </div>
            <h2 className="text-xl font-display font-semibold text-slate-100">{audit.profileName}</h2>
          </div>

          <div className="flex flex-wrap items-center gap-2 no-print">
            <button
              type="button"
              onClick={handleExportMarkdown}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-colors whitespace-nowrap shrink-0"
            >
              <FileText className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Exporter Markdown (.md)</span>
            </button>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <FileJson className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Exporter JSON</span>
            </button>

            <button
              type="button"
              onClick={handlePrint}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Printer className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Imprimer / PDF</span>
            </button>
          </div>
        </div>

        {/* Posture & Projected Score */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 pt-5">
          <div>
            <p className="text-xs text-slate-400">Niveau de risque global</p>
            <p className="mt-1 text-lg font-display font-semibold text-slate-100">
              {audit.summary.globalRiskLevel}
            </p>
          </div>

          <div>
            <p className="text-xs text-slate-400">Indice actuel</p>
            <p className="mt-1 text-lg font-display font-semibold tabular-nums text-slate-100">
              {projection.currentScore} / 100
            </p>
          </div>

          <div>
            <p className="text-xs text-slate-400">Score projeté après plan d’action</p>
            <p className="mt-1 text-lg font-display font-semibold tabular-nums text-emerald-400">
              {projection.projectedScore} / 100
            </p>
          </div>

          <div>
            <p className="text-xs text-slate-400">Recommandations validées</p>
            <p className="mt-1 text-lg font-display font-semibold tabular-nums text-cyan-300">
              {projection.resolvedCount} / {projection.totalCount}
            </p>
          </div>
        </div>
      </section>

      {/* Exposure summary per device */}
      <section className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden print-surface">
        <div className="p-4 border-b border-slate-800">
          <h3 className="text-base font-semibold text-slate-100">Synthèse des résultats par appareil</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-medium text-slate-400 bg-[#0F172A]/60">
                <th className="py-3 px-4">Appareil</th>
                <th className="py-3 px-4">Adresse IP</th>
                <th className="py-3 px-4">Services exposés (ports ouverts)</th>
                <th className="py-3 px-4 text-right">Risques identifiés</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {audit.devices.map((device) => {
                const openPorts = device.ports.filter((p) => p.state === 'open');
                const deviceFindings = audit.findings.filter((f) => f.deviceId === device.id);
                return (
                  <tr key={device.id}>
                    <td className="py-3 px-4 font-medium text-slate-100">{device.hostname}</td>
                    <td className="py-3 px-4 font-mono text-cyan-300 tabular-nums">{device.ip}</td>
                    <td className="py-3 px-4 text-slate-300 font-mono">
                      {openPorts.length > 0
                        ? openPorts.map((p) => `${p.port}/${p.service}`).join(', ')
                        : 'Aucun port ouvert'}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-200">
                      {deviceFindings.length}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Prioritized Recommendations & Interactive Checklist */}
      <section className="space-y-4">
        <div>
          <h3 className="text-base font-semibold text-slate-100">
            Plan d’action et recommandations de sécurisation
          </h3>
          <p className="text-xs text-slate-400">
            Cochez les mesures appliquées pour simuler l’amélioration de l’indice de durcissement et inclure l’état dans l’export
          </p>
        </div>

        {audit.findings.length === 0 ? (
          <div className="bg-[#111827] border border-slate-800 rounded-xl p-8 text-center print-surface">
            <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-100">
              Posture conforme : aucune correction urgente requise.
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Maintenez la surveillance régulière et les mises à jour automatiques de sécurité.
            </p>
          </div>
        ) : (
          PRIORITY_SECTION.map((group) => {
            const items = audit.findings.filter((f) => f.priority === group.priority);
            if (items.length === 0) return null;

            return (
              <div
                key={group.priority}
                className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden print-surface"
              >
                <div className="p-4 border-b border-slate-800">
                  <h4 className="text-sm font-semibold text-slate-100">{group.title}</h4>
                  <p className="text-xs text-slate-400 mt-0.5">{group.subtitle}</p>
                </div>

                <div className="divide-y divide-slate-800/70">
                  {items.map((finding) => {
                    const isChecked = resolvedFindingIds.has(finding.id);
                    return (
                      <div key={finding.id} className="p-4 flex items-start gap-3">
                        <input
                          id={`rem-${finding.id}`}
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => onToggleResolved(finding.id)}
                          className="mt-1 h-4 w-4 rounded border-slate-600 bg-[#0B1120] text-cyan-500 focus:ring-cyan-500 cursor-pointer no-print"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <label
                              htmlFor={`rem-${finding.id}`}
                              className={`text-sm font-medium cursor-pointer ${
                                isChecked ? 'line-through text-slate-500' : 'text-slate-100'
                              }`}
                            >
                              {finding.title}
                            </label>
                            <SeverityBadge severity={finding.severity} />
                          </div>

                          <div className="mt-1 text-xs text-slate-400 flex flex-wrap items-center gap-2">
                            <span className="font-mono text-cyan-300">
                              {finding.deviceIp}
                              {finding.port ? `:${finding.port}` : ''}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span>{finding.deviceHostname}</span>
                            {finding.cve && (
                              <>
                                <span aria-hidden="true">·</span>
                                <span className="font-mono">{finding.cve}</span>
                              </>
                            )}
                          </div>

                          <p className="mt-2 text-xs text-slate-200">{finding.recommendation}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })
        )}
      </section>
    </div>
  );
}
