import { Cpu, Database, Monitor, Printer, Router, Server, Shield } from 'lucide-react';
import type { DeviceType, NetworkDevice, SecurityFinding, Severity } from '../types/network';
import { getDeviceHighestSeverity } from '../utils/auditEngine';

interface TopologyMapProps {
  devices: NetworkDevice[];
  findings: SecurityFinding[];
  selectedDeviceId: string | null;
  onSelectDevice: (deviceId: string) => void;
  isScanning: boolean;
  discoveredCount: number;
}

const NODE_ACCENT: Record<Severity | 'safe', { stroke: string; fill: string; text: string }> = {
  critical: { stroke: '#ef4444', fill: 'rgba(239, 68, 68, 0.14)', text: '#fca5a5' },
  high: { stroke: '#f59e0b', fill: 'rgba(245, 158, 11, 0.14)', text: '#fcd34d' },
  medium: { stroke: '#06b6d4', fill: 'rgba(6, 182, 212, 0.14)', text: '#67e8f9' },
  low: { stroke: '#64748b', fill: 'rgba(100, 116, 139, 0.16)', text: '#cbd5e1' },
  safe: { stroke: '#10b981', fill: 'rgba(16, 185, 129, 0.14)', text: '#6ee7b7' },
};

function DeviceIcon({ type, className }: { type: DeviceType; className?: string }) {
  switch (type) {
    case 'gateway':
      return <Router className={className} aria-hidden="true" />;
    case 'firewall':
      return <Shield className={className} aria-hidden="true" />;
    case 'database':
      return <Database className={className} aria-hidden="true" />;
    case 'workstation':
      return <Monitor className={className} aria-hidden="true" />;
    case 'printer':
      return <Printer className={className} aria-hidden="true" />;
    case 'iot':
      return <Cpu className={className} aria-hidden="true" />;
    default:
      return <Server className={className} aria-hidden="true" />;
  }
}

export function TopologyMap({
  devices,
  findings,
  selectedDeviceId,
  onSelectDevice,
  isScanning,
  discoveredCount,
}: TopologyMapProps) {
  const visibleDevices = isScanning ? devices.slice(0, Math.max(1, discoveredCount)) : devices;
  const gateway = visibleDevices.find((d) => d.isGateway) ?? visibleDevices[0];
  const satellites = visibleDevices.filter((d) => d.id !== gateway?.id);

  const width = 640;
  const height = 380;
  const cx = width / 2;
  const cy = height / 2;
  const radiusX = 215;
  const radiusY = 128;

  const positioned = satellites.map((device, idx) => {
    const angle = (idx / Math.max(1, satellites.length)) * Math.PI * 2 - Math.PI / 2;
    return {
      device,
      x: cx + Math.cos(angle) * radiusX,
      y: cy + Math.sin(angle) * radiusY,
    };
  });

  return (
    <div className="relative bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 sm:gap-4 mb-3">
        <div>
          <h2 className="text-base font-semibold text-slate-100">Cartographie du réseau</h2>
          <p className="text-xs text-slate-400">
            Sélectionnez un nœud pour inspecter ses ports et vulnérabilités
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs text-slate-400 shrink-0">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-red-500/80" aria-hidden="true" />
            Critique
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/80" aria-hidden="true" />
            Élevé
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/80" aria-hidden="true" />
            Sain
          </span>
        </div>
      </div>

      <div className="relative w-full min-h-[260px] sm:aspect-[16/10] bg-[#0B1120] border border-slate-800/80 rounded-lg overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full select-none"
          role="img"
          aria-label="Topologie des appareils connectés sur le réseau"
        >
          <defs>
            <pattern id="cyber-grid" width="32" height="32" patternUnits="userSpaceOnUse">
              <path d="M 32 0 L 0 0 0 32" fill="none" stroke="rgba(148, 163, 184, 0.06)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width={width} height={height} fill="url(#cyber-grid)" />

          {isScanning && (
            <circle
              cx={cx}
              cy={cy}
              r="140"
              fill="none"
              stroke="rgba(6, 182, 212, 0.25)"
              strokeWidth="1.5"
              strokeDasharray="6 6"
            />
          )}

          {/* Connections from gateway to satellites */}
          {gateway &&
            positioned.map(({ device, x, y }) => {
              const risk = getDeviceHighestSeverity(device, findings);
              const isSelected = selectedDeviceId === device.id;
              return (
                <line
                  key={`link-${device.id}`}
                  x1={cx}
                  y1={cy}
                  x2={x}
                  y2={y}
                  stroke={isSelected ? '#06b6d4' : risk === 'critical' ? 'rgba(239,68,68,0.45)' : 'rgba(100,116,139,0.4)'}
                  strokeWidth={isSelected ? 2 : 1.25}
                  strokeDasharray={risk === 'critical' ? '4 3' : undefined}
                />
              );
            })}

          {/* Gateway central node */}
          {gateway && (() => {
            const risk = getDeviceHighestSeverity(gateway, findings);
            const palette = NODE_ACCENT[risk];
            const isSelected = selectedDeviceId === gateway.id;
            return (
              <g
                key={gateway.id}
                transform={`translate(${cx}, ${cy})`}
                className="cursor-pointer focus:outline-none"
                role="button"
                tabIndex={0}
                aria-label={`Sélectionner ${gateway.hostname} (${gateway.ip})`}
                onClick={() => onSelectDevice(gateway.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectDevice(gateway.id);
                  }
                }}
              >
                <circle
                  r={isSelected ? 34 : 30}
                  fill={palette.fill}
                  stroke={isSelected ? '#06b6d4' : palette.stroke}
                  strokeWidth={isSelected ? 2.5 : 1.75}
                />
                <foreignObject x="-12" y="-12" width="24" height="24" className="pointer-events-none">
                  <div className="w-6 h-6 flex items-center justify-center text-slate-100">
                    <DeviceIcon type={gateway.deviceType} className="w-5 h-5" />
                  </div>
                </foreignObject>
                <text
                  y="48"
                  textAnchor="middle"
                  className="fill-slate-100 text-[11px] font-medium"
                  style={{ fontFamily: 'var(--font-sans)' }}
                >
                  {gateway.hostname.split('.')[0]}
                </text>
                <text
                  y="62"
                  textAnchor="middle"
                  className="fill-cyan-300 text-[10px]"
                  style={{ fontFamily: 'var(--font-mono)' }}
                >
                  {gateway.ip}
                </text>
              </g>
            );
          })()}

          {/* Satellite device nodes */}
          {positioned.map(({ device, x, y }) => {
            const risk = getDeviceHighestSeverity(device, findings);
            const palette = NODE_ACCENT[risk];
            const isSelected = selectedDeviceId === device.id;
            const openCount = device.ports.filter((p) => p.state === 'open').length;

            return (
              <g
                key={device.id}
                transform={`translate(${x}, ${y})`}
                className="cursor-pointer focus:outline-none"
                role="button"
                tabIndex={0}
                aria-label={`Sélectionner ${device.hostname} (${device.ip}), ${openCount} ports ouverts`}
                onClick={() => onSelectDevice(device.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectDevice(device.id);
                  }
                }}
              >
                <circle
                  r={isSelected ? 26 : 22}
                  fill={palette.fill}
                  stroke={isSelected ? '#06b6d4' : palette.stroke}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                />
                <foreignObject x="-10" y="-10" width="20" height="20" className="pointer-events-none">
                  <div className="w-5 h-5 flex items-center justify-center text-slate-100">
                    <DeviceIcon type={device.deviceType} className="w-4 h-4" />
                  </div>
                </foreignObject>
                <text
                  y="37"
                  textAnchor="middle"
                  className="fill-slate-200 text-[10.5px] font-medium"
                  style={{ fontFamily: 'var(--font-sans)' }}
                >
                  {device.hostname.split('.')[0]}
                </text>
                <text
                  y="50"
                  textAnchor="middle"
                  className="fill-slate-400 text-[9.5px]"
                  style={{ fontFamily: 'var(--font-mono)' }}
                >
                  {device.ip}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
