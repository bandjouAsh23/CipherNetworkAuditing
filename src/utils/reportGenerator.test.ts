import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateNetworkAudit } from './auditEngine';
import { calculateProjectedScore, generateJsonReport, generateMarkdownReport } from './reportGenerator';
import { NETWORK_AUDIT_PROFILES } from '../data/auditProfiles';

test('reportGenerator generates complete Markdown and JSON audit reports', () => {
  const profile = NETWORK_AUDIT_PROFILES[0];
  const audit = evaluateNetworkAudit({
    id: 'test-report',
    profileName: profile.name,
    subnet: profile.subnet,
    sourceType: 'profile',
    devices: profile.devices,
  });

  const md = generateMarkdownReport(audit);
  assert.match(md, /# Rapport d'Audit de Sécurité Réseau/);
  assert.match(md, /192\.168\.10\.15/);
  assert.match(md, /Synthèse Exécutive/);
  assert.match(md, /Recommandations Générales de Durcissement Réseau/);

  const resolvedSet = new Set(audit.findings.slice(0, 2).map((f) => f.id));
  const projection = calculateProjectedScore(audit, resolvedSet);
  assert.equal(projection.resolvedCount, 2);
  assert.ok(projection.projectedScore > projection.currentScore);

  const json = JSON.parse(generateJsonReport(audit, resolvedSet));
  assert.equal(json.summary.totalDevices, profile.devices.length);
  assert.equal(json.remediationProgress.resolvedCount, 2);
});
