import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapXml, parseScanInput } from './nmapParser';
import { SAMPLE_NMAP_XML } from '../data/auditProfiles';

test('parseNmapXml extracts hosts, IP, MAC, hostnames, and open/closed/filtered ports', () => {
  const { devices, subnetLabel } = parseNmapXml(SAMPLE_NMAP_XML);
  assert.equal(subnetLabel, '172.16.40.0/24');
  assert.equal(devices.length, 2);

  assert.equal(devices[0].ip, '172.16.40.1');
  assert.equal(devices[0].hostname, 'gw-agence.lab.local');
  assert.equal(devices[0].vendor, 'VMware');
  assert.equal(devices[0].ports[1].state, 'filtered');

  assert.equal(devices[1].ip, '172.16.40.25');
  assert.equal(devices[1].ports.length, 4);
  assert.equal(devices[1].ports[1].product, 'Apache httpd');
  assert.equal(devices[1].ports[1].version, '2.4.49');
  assert.equal(devices[1].ports[3].state, 'closed');
});

test('parseScanInput parses JSON device inventory and throws on invalid input', () => {
  const jsonInput = JSON.stringify({
    devices: [
      {
        ip: '192.168.50.10',
        hostname: 'app-test.local',
        ports: [{ port: 22, protocol: 'tcp', state: 'open', service: 'ssh', product: 'OpenSSH', version: '9.8p1' }],
      },
    ],
  });

  const parsed = parseScanInput(jsonInput);
  assert.equal(parsed.devices.length, 1);
  assert.equal(parsed.devices[0].hostname, 'app-test.local');
  assert.equal(parsed.subnetLabel, '192.168.50.0/24');

  assert.throws(() => parseScanInput('not valid xml or json'), /Format non reconnu/);
});
