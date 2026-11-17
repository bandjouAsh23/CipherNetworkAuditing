import assert from 'node:assert/strict';
import test from 'node:test';
import { buildPythonZipAppBuffer, buildZipBuffer, crc32 } from './zipBuilder.ts';

test('crc32 computes standard IEEE 802.3 checksum', () => {
  assert.equal(crc32(Buffer.from('123456789', 'utf8')), 0xcbf43926);
});

test('buildZipBuffer produces valid PKZIP archive with EOCD signature', () => {
  const zip = buildZipBuffer([
    { name: 'hello.txt', data: 'CipherNetworkAuditing' },
    { name: 'run.sh', data: '#!/bin/sh\necho ok\n', executable: true },
  ]);
  assert.equal(zip.subarray(0, 4).toString('binary'), 'PK\x03\x04');
  // EOCD signature near end
  assert.equal(zip.readUInt32LE(zip.length - 22), 0x06054b50);
});

test('buildPythonZipAppBuffer prepends python3 shebang to valid zip payload', () => {
  const pyz = buildPythonZipAppBuffer([
    { name: '__main__.py', data: 'print("ok")\n' },
  ]);
  assert.equal(pyz.subarray(0, 23).toString('utf8'), '#!/usr/bin/env python3\n');
  assert.equal(pyz.subarray(23, 27).toString('binary'), 'PK\x03\x04');
});
