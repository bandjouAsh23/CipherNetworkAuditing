import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';
import { buildPcExecutableArchive, buildPcPortableBundle } from '../src/utils/pcBundleBuilder.ts';

const rootDir = process.cwd();
const desktopOutDir = path.join(rootDir, 'dist-desktop');

async function main() {
  console.log('[1/4] Compilation de l’interface 3D (Vite)...');
  execSync('npx vite build', { stdio: 'inherit', cwd: rootDir });

  fs.mkdirSync(desktopOutDir, { recursive: true });

  console.log('[2/4] Empaquetage du serveur backend autonome (esbuild)...');
  await build({
    entryPoints: [path.join(rootDir, 'server.ts')],
    outfile: path.join(desktopOutDir, 'ciphernetwork-backend.cjs'),
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    external: ['vite'],
    minify: true,
    define: {
      'process.env.NODE_ENV': '"production"',
    },
  });

  console.log('[3/4] Génération de l’exécutable PC autonome (.pyz / .pyzw)...');
  const pyz = buildPcExecutableArchive(rootDir);
  const pyzPath = path.join(desktopOutDir, 'CipherNetworkAuditing.pyz');
  const pyzwPath = path.join(desktopOutDir, 'CipherNetworkAuditing.pyzw');
  fs.writeFileSync(pyzPath, pyz, { mode: 0o755 });
  fs.writeFileSync(pyzwPath, pyz, { mode: 0o755 });

  console.log('[4/4] Création du pack portable PC (.zip)...');
  const zip = buildPcPortableBundle(rootDir, 'https://localhost:3000');
  const zipPath = path.join(desktopOutDir, 'CipherNetworkAuditing-PC-Portable.zip');
  fs.writeFileSync(zipPath, zip);

  console.log('Terminé ! Artefacts générés dans dist-desktop/ :');
  console.log(' - CipherNetworkAuditing.pyz');
  console.log(' - CipherNetworkAuditing.pyzw');
  console.log(' - CipherNetworkAuditing-PC-Portable.zip');
  console.log(' - ciphernetwork-backend.cjs');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
