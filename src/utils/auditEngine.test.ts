import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateNetworkAudit,
  inspectPortSecurity,
  isVersionInRange,
  isVersionLessThan,
} from './auditEngine';
import type { NetworkDevice } from '../types/network';

test('version comparison detects obsolete and vulnerable ranges accurately', () => {
  assert.equal(isVersionLessThan('8.2p1', [8, 5, 0]), true);
  assert.equal(isVersionLessThan('9.8p1', [8, 5, 0]), false);
  assert.equal(isVersionInRange('8.9p1', [8, 5, 0], [9, 7, 9]), true);
  assert.equal(isVersionInRange('9.8p1', [8, 5, 0], [9, 7, 9]), false);
});

test('inspectPortSecurity detects vulnerable versions and misconfigurations on open ports only', () => {
  const device: NetworkDevice = {
    id: 'test-srv',
    ip: '192.168.10.50',
    hostname: 'srv-test.local',
    deviceType: 'server',
    ports: [
      {
        port: 23,
        protocol: 'tcp',
        state: 'open',
        service: 'telnet',
      },
      {
        port: 80,
        protocol: 'tcp',
        state: 'open',
        service: 'http',
        product: 'Apache httpd',
        version: '2.4.50',
      },
      {
        port: 6379,
        protocol: 'tcp',
        state: 'open',
        service: 'redis',
        product: 'Redis',
        version: '7.2.0',
        authRequired: false,
      },
      {
        port: 21,
        protocol: 'tcp',
        state: 'closed',
        service: 'ftp',
        product: 'vsftpd',
        version: '2.3.4',
      },
    ],
  };

  const telnetFindings = inspectPortSecurity(device, device.ports[0]);
  assert.equal(telnetFindings.length, 1);
  assert.equal(telnetFindings[0].severity, 'critical');
  assert.equal(telnetFindings[0].category, 'misconfiguration');

  const apacheFindings = inspectPortSecurity(device, device.ports[1]);
  assert.equal(apacheFindings.length, 1);
  assert.equal(apacheFindings[0].severity, 'critical');
  assert.equal(apacheFindings[0].category, 'vulnerable_version');
  assert.match(apacheFindings[0].cve ?? '', /CVE-2021-41773/);

  const redisFindings = inspectPortSecurity(device, device.ports[2]);
  assert.equal(redisFindings.length, 1);
  assert.equal(redisFindings[0].category, 'misconfiguration');

  const closedFtpFindings = inspectPortSecurity(device, device.ports[3]);
  assert.equal(closedFtpFindings.length, 0);
});

test('evaluateNetworkAudit computes accurate port counts and hardening score', () => {
  const result = evaluateNetworkAudit({
    id: 'audit-1',
    profileName: 'Test LAN',
    subnet: '10.0.0.0/24',
    sourceType: 'profile',
    devices: [
      {
        id: 'd1',
        ip: '10.0.0.1',
        hostname: 'gw.local',
        deviceType: 'gateway',
        ports: [
          { port: 443, protocol: 'tcp', state: 'open', service: 'https', product: 'nginx', version: '1.26.1', tlsEnabled: true },
          { port: 22, protocol: 'tcp', state: 'filtered', service: 'ssh', product: 'OpenSSH', version: '9.8p1' },
          { port: 23, protocol: 'tcp', state: 'closed', service: 'telnet' },
        ],
      },
    ],
  });

  assert.equal(result.summary.totalDevices, 1);
  assert.equal(result.summary.openPorts, 1);
  assert.equal(result.summary.filteredPorts, 1);
  assert.equal(result.summary.closedPorts, 1);
  assert.equal(result.summary.hardeningScore, 100);
  assert.equal(result.summary.globalRiskLevel, 'Faible');
});
