export type PortState = 'open' | 'closed' | 'filtered';

export type Protocol = 'tcp' | 'udp';

export type DeviceType =
  | 'gateway'
  | 'firewall'
  | 'server'
  | 'database'
  | 'workstation'
  | 'iot'
  | 'printer'
  | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FindingCategory = 'vulnerable_version' | 'misconfiguration';

export type RemediationPriority = 'P1' | 'P2' | 'P3';

export interface PortEntry {
  port: number;
  protocol: Protocol;
  state: PortState;
  service: string;
  product?: string;
  version?: string;
  banner?: string;
  tlsEnabled?: boolean;
  authRequired?: boolean;
  configNotes?: string;
}

export interface NetworkDevice {
  id: string;
  ip: string;
  hostname: string;
  mac?: string;
  vendor?: string;
  os?: string;
  deviceType: DeviceType;
  latencyMs?: number;
  isGateway?: boolean;
  ports: PortEntry[];
}

export interface SecurityFinding {
  id: string;
  deviceId: string;
  deviceIp: string;
  deviceHostname: string;
  port?: number;
  protocol?: Protocol;
  service: string;
  detectedVersion?: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  cve?: string;
  cvss?: number;
  description: string;
  riskImpact: string;
  recommendation: string;
  remediationSteps: string[];
  priority: RemediationPriority;
}

export type GlobalRiskLevel = 'Critique' | 'Élevé' | 'Modéré' | 'Faible';

export interface AuditSummary {
  totalDevices: number;
  openPorts: number;
  closedPorts: number;
  filteredPorts: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  hardeningScore: number;
  globalRiskLevel: GlobalRiskLevel;
}

export type AuditSourceType = 'profile' | 'local_host' | 'nmap_import' | 'target_scan';

export interface NetworkAuditResult {
  id: string;
  profileName: string;
  subnet: string;
  sourceType: AuditSourceType;
  scannedAt: string;
  durationMs: number;
  devices: NetworkDevice[];
  findings: SecurityFinding[];
  summary: AuditSummary;
}

export interface NetworkProfile {
  id: string;
  name: string;
  subnet: string;
  description: string;
  environmentLabel: string;
  devices: NetworkDevice[];
}
