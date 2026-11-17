import assert from 'node:assert/strict';
import test from 'node:test';
import { enforceHttpsUrl, validateAuthorizedTarget } from './targetValidation.ts';

test('validateAuthorizedTarget rejects missing permission confirmation', () => {
  const res = validateAuthorizedTarget('192.168.1.10', false);
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.status, 403);
  }
});

test('validateAuthorizedTarget blocks cloud metadata and multicast addresses', () => {
  const meta = validateAuthorizedTarget('169.254.169.254', true);
  assert.equal(meta.ok, false);

  const multicast = validateAuthorizedTarget('224.0.0.1', true);
  assert.equal(multicast.ok, false);
});

test('validateAuthorizedTarget validates loopback, RFC1918 IP, and /24 CIDR', () => {
  const loopback = validateAuthorizedTarget('127.0.0.1', true);
  assert.equal(loopback.ok, true);
  if (loopback.ok) {
    assert.equal(loopback.value.scope, 'loopback');
    assert.deepEqual(loopback.value.hostIps, ['127.0.0.1']);
  }

  const cidr = validateAuthorizedTarget('192.168.10.45/24', true);
  assert.equal(cidr.ok, true);
  if (cidr.ok) {
    assert.equal(cidr.value.scope, 'private_rfc1918');
    assert.equal(cidr.value.normalizedTarget, '192.168.10.0/24');
    assert.equal(cidr.value.hostIps[0], '192.168.10.1');
  }
});

test('enforceHttpsUrl upgrades plain HTTP URLs to HTTPS', () => {
  assert.equal(enforceHttpsUrl('http://audit.exemple.fr'), 'https://audit.exemple.fr');
  assert.equal(enforceHttpsUrl('https://audit.exemple.fr'), 'https://audit.exemple.fr');
  assert.equal(enforceHttpsUrl('http://localhost:3000'), 'https://localhost:3000');
});
