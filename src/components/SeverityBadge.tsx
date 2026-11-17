import { AlertOctagon, AlertTriangle, CheckCircle2, Info, Lock, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react';
import type { PortState, Severity } from '../types/network';

export const SEVERITY_META: Record<
  Severity | 'safe',
  { label: string; textClass: string; bgClass: string; borderClass: string }
> = {
  critical: {
    label: 'Critique',
    textClass: 'text-red-300',
    bgClass: 'bg-red-500/15',
    borderClass: 'border-red-500/40',
  },
  high: {
    label: 'Élevé',
    textClass: 'text-amber-300',
    bgClass: 'bg-amber-500/15',
    borderClass: 'border-amber-500/40',
  },
  medium: {
    label: 'Moyen',
    textClass: 'text-cyan-300',
    bgClass: 'bg-cyan-500/15',
    borderClass: 'border-cyan-500/40',
  },
  low: {
    label: 'Faible',
    textClass: 'text-slate-300',
    bgClass: 'bg-slate-700/40',
    borderClass: 'border-slate-600/50',
  },
  safe: {
    label: 'Sain',
    textClass: 'text-emerald-300',
    bgClass: 'bg-emerald-500/15',
    borderClass: 'border-emerald-500/40',
  },
};

export function SeverityBadge({ severity }: { severity: Severity | 'safe' }) {
  const meta = SEVERITY_META[severity];

  const Icon =
    severity === 'critical'
      ? AlertOctagon
      : severity === 'high'
        ? AlertTriangle
        : severity === 'medium'
          ? ShieldAlert
          : severity === 'low'
            ? Info
            : ShieldCheck;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded border whitespace-nowrap shrink-0 ${meta.bgClass} ${meta.textClass} ${meta.borderClass}`}
    >
      <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>{meta.label}</span>
    </span>
  );
}

export function PortStateBadge({ state }: { state: PortState }) {
  if (state === 'open') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded border bg-emerald-500/15 text-emerald-300 border-emerald-500/40 whitespace-nowrap shrink-0">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Ouvert</span>
      </span>
    );
  }
  if (state === 'filtered') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded border bg-amber-500/15 text-amber-300 border-amber-500/40 whitespace-nowrap shrink-0">
        <Lock className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Filtré</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded border bg-slate-800 text-slate-400 border-slate-700 whitespace-nowrap shrink-0">
      <ShieldOff className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
      <span>Fermé</span>
    </span>
  );
}
