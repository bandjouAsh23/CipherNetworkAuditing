import express from 'express';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { evaluateNetworkAudit } from './src/utils/auditEngine.ts';
import { parseScanInput } from './src/utils/nmapParser.ts';
import { buildPcExecutableArchive, buildPcPortableBundle } from './src/utils/pcBundleBuilder.ts';
import { enforceHttpsUrl, validateAuthorizedTarget } from './src/utils/targetValidation.ts';
import type { NetworkDevice, PortEntry } from './src/types/network.ts';

const PORT = 3000;

const WELL_KNOWN_SERVICES: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'domain',
  80: 'http',
  443: 'https',
  3000: 'http-app',
  3306: 'mysql',
  5432: 'postgresql',
  6379: 'redis',
  8080: 'http-proxy',
};

function readListeningPortsFromProc(): Set<number> {
  const listening = new Set<number>();
  const files = ['/proc/net/tcp', '/proc/net/tcp6'];

  for (const file of files) {
    try {
      if (!fs.existsSync(file)) continue;
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n').slice(1);
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 4) continue;
        // st == '0A' means TCP_LISTEN
        if (cols[3] === '0A') {
          const hexPort = cols[1].split(':')[1];
          if (hexPort) {
            const portNum = Number.parseInt(hexPort, 16);
            if (!Number.isNaN(portNum) && portNum > 0) {
              listening.add(portNum);
            }
          }
        }
      }
    } catch {
      // Ignore if /proc is restricted
    }
  }

  return listening;
}

function probeTcpPort(
  host: string,
  port: number,
  timeoutMs = 220
): Promise<'open' | 'closed' | 'filtered'> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (result: 'open' | 'closed' | 'filtered') => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('filtered'));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') {
        finish('closed');
      } else {
        finish('filtered');
      }
    });
    socket.connect(port, host);
  });
}

function probeLocalPort(port: number, timeoutMs = 150): Promise<'open' | 'closed'> {
  return probeTcpPort('127.0.0.1', port, timeoutMs).then((state) => (state === 'open' ? 'open' : 'closed'));
}

async function probeTargetIp(ip: string): Promise<NetworkDevice | null> {
  const start = Date.now();
  const targetPorts = [21, 22, 23, 25, 53, 80, 139, 443, 445, 3000, 3306, 3389, 5432, 6379, 8080, 8443];

  const results = await Promise.all(
    targetPorts.map(async (port) => {
      const state = await probeTcpPort(ip, port, 220);
      const entry: PortEntry = {
        port,
        protocol: 'tcp',
        state,
        service: WELL_KNOWN_SERVICES[port] ?? `tcp-${port}`,
        tlsEnabled: port === 443 || port === 8443 ? true : port === 80 || port === 8080 || port === 21 || port === 23 ? false : undefined,
      };
      return entry;
    })
  );

  const hasOpen = results.some((p) => p.state === 'open');
  const hasExplicitClosed = results.some((p) => p.state === 'closed');
  if (!hasOpen && !hasExplicitClosed) {
    return null;
  }

  let hostname = ip === '127.0.0.1' ? os.hostname() || 'localhost' : `hote-${ip.replace(/\./g, '-')}.local`;
  try {
    const ptrs = await dns.reverse(ip);
    if (ptrs[0]) hostname = ptrs[0];
  } catch {
    // Reverse DNS optional
  }

  return {
    id: `target-${ip.replace(/\./g, '-')}`,
    ip,
    hostname,
    deviceType: ip.endsWith('.1') || ip.endsWith('.254') ? 'gateway' : 'server',
    latencyMs: Number(Math.max(0.4, (Date.now() - start) / targetPorts.length).toFixed(1)),
    isGateway: ip.endsWith('.1') || ip.endsWith('.254'),
    ports: results.filter((p) => p.state === 'open' || p.port === 22 || p.port === 80 || p.port === 443),
  };
}

async function inspectLocalHost(): Promise<{ devices: NetworkDevice[]; subnet: string }> {
  const start = Date.now();
  const interfaces = os.networkInterfaces();
  const hostname = os.hostname() || 'hote-local';
  const osInfo = `${os.type()} ${os.release()} (${os.arch()})`;

  const listeningPorts = readListeningPortsFromProc();
  const standardPorts = [22, 80, 443, 3000, 3306, 5432, 6379, 8080];
  const candidatePorts = Array.from(new Set([...standardPorts, ...Array.from(listeningPorts)])).sort((a, b) => a - b);

  const portChecks = await Promise.all(
    candidatePorts.map(async (port) => {
      const state = listeningPorts.has(port) ? 'open' : await probeLocalPort(port);
      const entry: PortEntry = {
        port,
        protocol: 'tcp',
        state,
        service: WELL_KNOWN_SERVICES[port] ?? `tcp-${port}`,
        product: port === 3000 ? 'Node.js / Express' : undefined,
        version: port === 3000 ? process.version : undefined,
        tlsEnabled: port === 443,
      };
      return entry;
    })
  );

  const devices: NetworkDevice[] = [];
  let primarySubnet = '127.0.0.0/8';

  for (const [ifaceName, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;
    const ipv4 = addrs.find((a) => a.family === 'IPv4');
    if (!ipv4) continue;

    const isLoopback = ipv4.internal;
    if (!isLoopback) {
      const octets = ipv4.address.split('.');
      if (octets.length === 4) {
        primarySubnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
      }
    }

    devices.push({
      id: `local-${ifaceName}`,
      ip: ipv4.address,
      hostname: isLoopback ? `${hostname} (loopback)` : `${hostname} (${ifaceName})`,
      mac: ipv4.mac && ipv4.mac !== '00:00:00:00:00:00' ? ipv4.mac.toUpperCase() : undefined,
      vendor: isLoopback ? 'Interface locale' : `Interface ${ifaceName}`,
      os: osInfo,
      deviceType: 'server',
      latencyMs: Number(((Date.now() - start) / Math.max(1, portChecks.length)).toFixed(1)),
      isGateway: false,
      ports: portChecks,
    });
  }

  if (devices.length === 0) {
    devices.push({
      id: 'local-fallback',
      ip: '127.0.0.1',
      hostname,
      os: osInfo,
      deviceType: 'server',
      latencyMs: 0.5,
      ports: portChecks,
    });
  }

  return { devices, subnet: primarySubnet };
}

async function startServer() {
  const app = express();
  app.set('trust proxy', true);

  const tlsCertPath = process.env.TLS_CERT_PATH;
  const tlsKeyPath = process.env.TLS_KEY_PATH;
  const hasNativeTls = Boolean(
    tlsCertPath && tlsKeyPath && fs.existsSync(tlsCertPath) && fs.existsSync(tlsKeyPath)
  );

  const httpServer = hasNativeTls
    ? https.createServer(
        {
          cert: fs.readFileSync(tlsCertPath as string),
          key: fs.readFileSync(tlsKeyPath as string),
        },
        app
      )
    : http.createServer(app);

  // Enforce HTTPS redirect behind reverse proxy in production + strict TLS/security headers
  app.use((req, res, next) => {
    const forwardedProto = req.headers['x-forwarded-proto'];
    const isHttps = req.secure || forwardedProto === 'https' || hasNativeTls;

    if (process.env.NODE_ENV === 'production' && forwardedProto === 'http' && req.headers.host) {
      res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
      return;
    }

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (isHttps) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.setHeader('Content-Security-Policy', 'upgrade-insecure-requests');
    }
    next();
  });

  app.use(express.json({ limit: '4mb' }));

  app.get('/api/health', (req, res) => {
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || hasNativeTls;
    res.json({
      ok: true,
      transport: isHttps ? 'HTTPS/TLS' : 'HTTP-LocalProxy',
      nativeTls: hasNativeTls,
    });
  });

  app.get('/api/local-host', async (_req, res) => {
    const start = Date.now();
    try {
      const { devices, subnet } = await inspectLocalHost();
      const audit = evaluateNetworkAudit({
        id: `local-${Date.now()}`,
        profileName: 'Audit Hôte Local (Système réel)',
        subnet,
        sourceType: 'local_host',
        devices,
        durationMs: Math.max(120, Date.now() - start),
      });
      res.json(audit);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : "Erreur lors de l'inspection de l'hôte local.",
      });
    }
  });

  app.post('/api/scan-target', async (req, res) => {
    const start = Date.now();
    const rawTarget = typeof req.body?.target === 'string' ? req.body.target : '';
    const authorized = req.body?.authorized === true;

    const validation = validateAuthorizedTarget(rawTarget, authorized);
    if (!validation.ok) {
      res.status(validation.status).json({ error: validation.error });
      return;
    }

    const { normalizedTarget, scope, hostIps } = validation.value;

    // Prevent arbitrary public internet scanning / SSRF relay from the cloud runtime
    if (scope === 'public') {
      res.status(403).json({
        error: `Pour éviter tout usage abusif depuis le cloud, l'analyse directe d'IP publiques (${normalizedTarget}) doit être exécutée depuis votre poste autorisé via l'agent Python (cipher_audit_pc.py --target ${normalizedTarget} --authorized) ou via import Nmap XML.`,
        localCommand: `python3 cipher_audit_pc.py --target ${normalizedTarget} --authorized`,
      });
      return;
    }

    try {
      const probed = await Promise.all(hostIps.map((ip) => probeTargetIp(ip)));
      const reachableDevices = probed.filter((d): d is NetworkDevice => d !== null);

      if (reachableDevices.length === 0) {
        res.json({
          reachable: false,
          target: normalizedTarget,
          message: `La cible privée ${normalizedTarget} n'est pas directement joignable depuis cet environnement isolé. Exécutez l'agent local sur votre PC pour la sonder et transférer le résultat en HTTPS.`,
          localCommand: `python3 cipher_audit_pc.py --target ${normalizedTarget} --authorized`,
        });
        return;
      }

      const audit = evaluateNetworkAudit({
        id: `target-${Date.now()}`,
        profileName: `Cible autorisée (${normalizedTarget})`,
        subnet: normalizedTarget,
        sourceType: 'target_scan',
        devices: reachableDevices,
        durationMs: Math.max(85, Date.now() - start),
      });

      res.json({
        reachable: true,
        target: normalizedTarget,
        audit,
      });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : "Erreur lors de l'analyse de la cible.",
      });
    }
  });

  app.get('/api/download-pc-executable', (req, res) => {
    try {
      const format = req.query.format === 'pyzw' ? 'pyzw' : 'pyz';
      const prebuilt = path.join(process.cwd(), 'dist-desktop', `CipherNetworkAuditing.${format}`);
      const buffer = fs.existsSync(prebuilt)
        ? fs.readFileSync(prebuilt)
        : buildPcExecutableArchive(process.cwd());

      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="CipherNetworkAuditing.${format}"`
      );
      res.send(buffer);
    } catch (err) {
      res.status(500).json({
        error:
          err instanceof Error
            ? err.message
            : "Impossible de générer l'exécutable PC.",
      });
    }
  });

  app.get('/api/download-pc-bundle', (req, res) => {
    try {
      const host = req.headers.host || 'localhost:3000';
      const httpsUrl = enforceHttpsUrl(`https://${host}`);
      const buffer = buildPcPortableBundle(process.cwd(), httpsUrl);

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="CipherNetworkAuditing-PC-Portable.zip"'
      );
      res.send(buffer);
    } catch (err) {
      res.status(500).json({
        error:
          err instanceof Error
            ? err.message
            : 'Impossible de générer le pack exécutable PC.',
      });
    }
  });

  app.post('/api/analyze-nmap', (req, res) => {
    const start = Date.now();
    try {
      const rawInput = typeof req.body?.rawInput === 'string' ? req.body.rawInput : '';
      const profileName =
        typeof req.body?.profileName === 'string' && req.body.profileName.trim()
          ? req.body.profileName.trim()
          : 'Scan Nmap Importé';

      const { devices, subnetLabel } = parseScanInput(rawInput);
      const audit = evaluateNetworkAudit({
        id: `import-${Date.now()}`,
        profileName,
        subnet: subnetLabel,
        sourceType: 'nmap_import',
        devices,
        durationMs: Math.max(45, Date.now() - start),
      });
      res.json(audit);
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Impossible d’analyser le fichier de scan fourni.',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR === 'true' ? false : { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    const protoLabel = hasNativeTls ? 'https' : 'http';
    console.log(`CipherNetworkAuditing listening on ${protoLabel}://0.0.0.0:${PORT}`);
  });
}

startServer();
