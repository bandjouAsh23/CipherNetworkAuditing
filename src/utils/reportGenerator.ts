import type { NetworkAuditResult, SecurityFinding, Severity } from '../types/network';
import { computeHardeningScore } from './auditEngine';

const SEVERITY_LABEL_FR: Record<Severity, string> = {
  critical: 'Critique',
  high: 'Élevé',
  medium: 'Moyen',
  low: 'Faible',
};

const PORT_STATE_LABEL_FR = {
  open: 'Ouvert',
  closed: 'Fermé',
  filtered: 'Filtré',
} as const;

export function calculateProjectedScore(
  audit: NetworkAuditResult,
  resolvedFindingIds: Set<string>
): { currentScore: number; projectedScore: number; resolvedCount: number; totalCount: number } {
  const remainingFindings = audit.findings.filter((f) => !resolvedFindingIds.has(f.id));
  const projectedScore = computeHardeningScore(remainingFindings);
  return {
    currentScore: audit.summary.hardeningScore,
    projectedScore,
    resolvedCount: audit.findings.length - remainingFindings.length,
    totalCount: audit.findings.length,
  };
}

export function generateMarkdownReport(
  audit: NetworkAuditResult,
  resolvedFindingIds: Set<string> = new Set()
): string {
  const { summary, devices, findings } = audit;
  const dateFr = new Date(audit.scannedAt).toLocaleString('fr-FR', {
    dateStyle: 'long',
    timeStyle: 'short',
  });

  const lines: string[] = [
    `# Rapport d'Audit de Sécurité Réseau — CipherNetworkAuditing (${audit.profileName})`,
    '',
    `- **Sous-réseau analysé** : \`${audit.subnet}\``,
    `- **Date de l'audit** : ${dateFr}`,
    `- **Niveau de risque global** : **${summary.globalRiskLevel}**`,
    `- **Indice de durcissement** : **${summary.hardeningScore} / 100**`,
    '',
    '## 1. Synthèse Exécutive',
    '',
    `| Indicateur | Valeur |`,
    `| --- | ---: |`,
    `| Appareils identifiés | ${summary.totalDevices} |`,
    `| Ports ouverts | ${summary.openPorts} |`,
    `| Ports filtrés | ${summary.filteredPorts} |`,
    `| Ports fermés | ${summary.closedPorts} |`,
    `| Anomalies Critiques | ${summary.criticalCount} |`,
    `| Anomalies Élevées | ${summary.highCount} |`,
    `| Anomalies Moyennes | ${summary.mediumCount} |`,
    `| Anomalies Faibles | ${summary.lowCount} |`,
    '',
    '## 2. Inventaire des Appareils et État des Ports',
    '',
    '| Nom d’hôte | Adresse IP | Système / Constructeur | Ports ouverts |',
    '| --- | --- | --- | --- |',
  ];

  for (const device of devices) {
    const openList = device.ports
      .filter((p) => p.state === 'open')
      .map((p) => `${p.port}/${p.protocol} (${p.service})`)
      .join(', ');
    lines.push(
      `| ${device.hostname} | \`${device.ip}\` | ${device.os ?? device.vendor ?? 'Non identifié'} | ${openList || 'Aucun'} |`
    );
  }

  lines.push('', '### Détail complet des ports par appareil', '');
  for (const device of devices) {
    lines.push(`#### ${device.hostname} (\`${device.ip}\`)`);
    if (device.ports.length === 0) {
      lines.push('- Aucun port sondé répertorié.');
    } else {
      for (const port of device.ports) {
        const versionStr = [port.product, port.version].filter(Boolean).join(' ');
        lines.push(
          `- **${port.port}/${port.protocol}** — État : *${PORT_STATE_LABEL_FR[port.state]}* — Service : \`${port.service}\`${versionStr ? ` (${versionStr})` : ''}`
        );
      }
    }
    lines.push('');
  }

  lines.push('## 3. Vulnérabilités et Mauvaises Configurations Détectées', '');

  if (findings.length === 0) {
    lines.push('Aucune vulnérabilité connue ni mauvaise configuration majeure n’a été relevée lors de cet audit.');
  } else {
    findings.forEach((finding: SecurityFinding, idx: number) => {
      const status = resolvedFindingIds.has(finding.id) ? '[TRAITÉ]' : '[À CORRIGER]';
      const categoryLabel =
        finding.category === 'vulnerable_version' ? 'Version vulnérable' : 'Mauvaise configuration';
      lines.push(
        `### ${idx + 1}. ${status} [${SEVERITY_LABEL_FR[finding.severity]}] ${finding.title}`,
        '',
        `- **Hôte concerné** : ${finding.deviceHostname} (\`${finding.deviceIp}\`)`,
        `- **Port / Service** : ${finding.port ? `${finding.port}/${finding.protocol}` : 'N/A'} (${finding.service}${finding.detectedVersion ? ` — ${finding.detectedVersion}` : ''})`,
        `- **Catégorie** : ${categoryLabel}${finding.cve ? ` · Référence : ${finding.cve}` : ''}`,
        `- **Priorité** : ${finding.priority}`,
        `- **Description** : ${finding.description}`,
        `- **Risque** : ${finding.riskImpact}`,
        `- **Recommandation principale** : ${finding.recommendation}`,
        '- **Plan d’action** :',
        ...finding.remediationSteps.map((step) => `  - ${step}`),
        ''
      );
    });
  }

  lines.push(
    '## 4. Recommandations Générales de Durcissement Réseau',
    '',
    '- Appliquer le principe du moindre privilège sur le pare-feu interne et bloquer les ports d’administration non utilisés.',
    '- Segmenter les équipements IoT et imprimantes dans des VLAN isolés du réseau serveur et bureautique.',
    '- Remplacer systématiquement les protocoles en clair (Telnet, FTP, HTTP admin) par leurs équivalents chiffrés (SSH, SFTP, HTTPS/TLS 1.3).',
    '- Planifier un cycle mensuel de mise à jour des services exposés et vérifier les bannières applicatives.',
    ''
  );

  return lines.join('\n');
}

export function generateJsonReport(
  audit: NetworkAuditResult,
  resolvedFindingIds: Set<string> = new Set()
): string {
  const projection = calculateProjectedScore(audit, resolvedFindingIds);
  return JSON.stringify(
    {
      reportTitle: `Rapport d'Audit de Sécurité Réseau — ${audit.profileName}`,
      generatedAt: new Date().toISOString(),
      auditMetadata: {
        id: audit.id,
        profileName: audit.profileName,
        subnet: audit.subnet,
        sourceType: audit.sourceType,
        scannedAt: audit.scannedAt,
        durationMs: audit.durationMs,
      },
      summary: audit.summary,
      remediationProgress: {
        ...projection,
        resolvedFindingIds: Array.from(resolvedFindingIds),
      },
      devices: audit.devices,
      findings: audit.findings.map((f) => ({
        ...f,
        remediationStatus: resolvedFindingIds.has(f.id) ? 'resolved' : 'open',
      })),
    },
    null,
    2
  );
}
