import fs from 'node:fs';
import path from 'node:path';
import { generatePythonPcAgent } from './pcAgentGenerator';
import { buildPythonZipAppBuffer, buildZipBuffer, type ZipEntryInput } from './zipBuilder';

function collectDirectoryEntries(dirPath: string, zipPrefix: string): ZipEntryInput[] {
  if (!fs.existsSync(dirPath)) return [];
  const entries: ZipEntryInput[] = [];

  const walk = (currentDir: string) => {
    for (const item of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        walk(fullPath);
      } else if (item.isFile()) {
        const rel = path.relative(dirPath, fullPath).replace(/\\/g, '/');
        entries.push({
          name: `${zipPrefix}/${rel}`,
          data: fs.readFileSync(fullPath),
        });
      }
    }
  };

  walk(dirPath);
  return entries;
}

export function buildPcExecutableArchive(rootDir: string): Buffer {
  const entryScriptPath = path.join(rootDir, 'desktop', 'pc_app_entry.py');
  const distDir = path.join(rootDir, 'dist');

  if (!fs.existsSync(entryScriptPath)) {
    throw new Error("Script d'entrée PC introuvable (desktop/pc_app_entry.py).");
  }
  if (!fs.existsSync(path.join(distDir, 'index.html'))) {
    throw new Error("Les fichiers compilés dist/ sont absents. Exécutez npm run build d'abord.");
  }

  const entries: ZipEntryInput[] = [
    {
      name: '__main__.py',
      data: fs.readFileSync(entryScriptPath),
      executable: true,
    },
    ...collectDirectoryEntries(distDir, 'dist'),
  ];

  return buildPythonZipAppBuffer(entries);
}

export function buildPcPortableBundle(rootDir: string, httpsAppUrl: string): Buffer {
  const pyzBuffer = buildPcExecutableArchive(rootDir);
  const distDir = path.join(rootDir, 'dist');
  const backendBundlePath = path.join(rootDir, 'dist-desktop', 'ciphernetwork-backend.cjs');

  const winLauncher = `@echo off
title CipherNetworkAuditing — Application PC
echo ========================================================
echo   CipherNetworkAuditing — Demarrage de l'application PC
echo ========================================================
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw "%~dp0CipherNetworkAuditing.pyzw"
  exit /b 0
)
where python >nul 2>nul
if %errorlevel%==0 (
  python "%~dp0CipherNetworkAuditing.pyz"
  exit /b 0
)
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%~dp0CipherNetworkAuditing.pyz"
  exit /b 0
)
where node >nul 2>nul
if %errorlevel%==0 if exist "%~dp0ciphernetwork-backend.cjs" (
  echo Demarrage via Node.js local...
  start "" msedge --app="http://127.0.0.1:3000" 2>nul || start "" chrome --app="http://127.0.0.1:3000" 2>nul
  set NODE_ENV=production
  node "%~dp0ciphernetwork-backend.cjs"
  exit /b 0
)
echo [INFO] Ouverture en mode application bureau HTTPS...
start "" msedge --app="${httpsAppUrl}" 2>nul || start "" chrome --app="${httpsAppUrl}" 2>nul || start "" "${httpsAppUrl}"
pause
`;

  const unixLauncher = `#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
chmod +x "$DIR/CipherNetworkAuditing.pyz" 2>/dev/null || true

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$DIR/CipherNetworkAuditing.pyz"
elif command -v node >/dev/null 2>&1 && [ -f "$DIR/ciphernetwork-backend.cjs" ]; then
  NODE_ENV=production exec node "$DIR/ciphernetwork-backend.cjs"
else
  echo "Installez Python 3 ou ouvrez ${httpsAppUrl}"
fi
`;

  const buildExeBat = `@echo off
echo Compilation de l'installateur Windows (.exe) via Electron Builder...
call npm install --no-save electron electron-builder
call npm run build:desktop
call npx electron-builder --win
pause
`;

  const readmeTxt = `CipherNetworkAuditing — Pack Exécutable PC Autonome
====================================================

Contenu du pack :
1. CipherNetworkAuditing.pyzw / CipherNetworkAuditing.pyz
   Exécutable autonome (Python 3 standard library uniquement, aucune installation requise).
   Il embarque toute l'interface 3D (Three.js) et le moteur d'inspection réseau local LAN.
   - Double-cliquez sur CipherNetworkAuditing.pyzw (Windows) ou exécutez ./CipherNetworkAuditing.pyz (Linux/macOS).
   - En ligne de commande (mode headless) :
     python3 CipherNetworkAuditing.pyz --cli --target 192.168.1.0/24 --authorized

2. Lancer_CipherNetworkAuditing.bat (Windows) / lancer_ciphernetwork.sh (Linux / macOS)
   Lanceurs directs en un clic.

3. cipher_audit_pc.py
   Agent scanner léger en ligne de commande avec support --upload-https-url.

4. Générer un installeur natif Windows (.exe) / Linux (.AppImage) / macOS (.dmg) :
   Depuis les sources du projet, exécutez : npm run build:desktop && npx electron-builder
`;

  const entries: ZipEntryInput[] = [
    { name: 'CipherNetworkAuditing.pyz', data: pyzBuffer, executable: true },
    { name: 'CipherNetworkAuditing.pyzw', data: pyzBuffer, executable: true },
    { name: 'Lancer_CipherNetworkAuditing.bat', data: winLauncher },
    { name: 'lancer_ciphernetwork.sh', data: unixLauncher, executable: true },
    { name: 'cipher_audit_pc.py', data: generatePythonPcAgent(), executable: true },
    { name: 'Build_Windows_EXE.bat', data: buildExeBat },
    { name: 'README-PC.txt', data: readmeTxt },
    ...collectDirectoryEntries(distDir, 'dist'),
  ];

  if (fs.existsSync(backendBundlePath)) {
    entries.push({
      name: 'ciphernetwork-backend.cjs',
      data: fs.readFileSync(backendBundlePath),
    });
  }

  return buildZipBuffer(entries);
}
