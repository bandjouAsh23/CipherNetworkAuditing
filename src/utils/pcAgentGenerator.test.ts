import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePythonPcAgent,
  generateUnixShellLauncher,
  generateWindowsBatchLauncher,
} from './pcAgentGenerator';

test('pcAgentGenerator creates valid Python scanner and OS launchers for CipherNetworkAuditing', () => {
  const py = generatePythonPcAgent();
  assert.match(py, /CipherNetworkAuditing/);
  assert.match(py, /def inspect_host/);
  assert.match(py, /ciphernetwork_scan\.json/);

  const bat = generateWindowsBatchLauncher('https://example.local');
  assert.match(bat, /--app="https:\/\/example\.local"/);
  assert.match(bat, /CipherNetworkAuditing/);

  const sh = generateUnixShellLauncher('https://example.local');
  assert.match(sh, /APP_URL="https:\/\/example\.local"/);
  assert.match(sh, /CipherNetworkAuditing/);
});
