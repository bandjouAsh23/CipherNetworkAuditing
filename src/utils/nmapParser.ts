import type { DeviceType, NetworkDevice, PortEntry, PortState, Protocol } from '../types/network';

function extractAttribute(tagText: string, attrName: string): string | undefined {
  const regex = new RegExp(`${attrName}=["']([^"']*)["']`, 'i');
  const match = tagText.match(regex);
  return match ? match[1] : undefined;
}

function inferDeviceType(hostname: string, os: string | undefined, ports: PortEntry[]): DeviceType {
  const lowerHost = hostname.toLowerCase();
  const lowerOs = (os ?? '').toLowerCase();

  if (lowerHost.includes('gw') || lowerHost.includes('router') || lowerHost.includes('gateway') || lowerHost.includes('fw')) {
    return lowerHost.includes('fw') ? 'firewall' : 'gateway';
  }
  if (lowerHost.includes('printer') || lowerHost.includes('hp-') || ports.some((p) => p.port === 9100 && p.state === 'open')) {
    return 'printer';
  }
  if (
    lowerHost.includes('db') ||
    lowerHost.includes('sql') ||
    lowerHost.includes('mongo') ||
    lowerHost.includes('redis') ||
    ports.some((p) => [3306, 5432, 27017, 6379].includes(p.port) && p.state === 'open')
  ) {
    return 'database';
  }
  if (lowerHost.includes('cam') || lowerHost.includes('iot') || lowerOs.includes('embedded')) {
    return 'iot';
  }
  if (
    lowerHost.includes('srv') ||
    lowerHost.includes('web') ||
    lowerHost.includes('app') ||
    lowerOs.includes('linux') ||
    lowerOs.includes('ubuntu') ||
    lowerOs.includes('debian')
  ) {
    return 'server';
  }
  if (lowerOs.includes('windows 10') || lowerOs.includes('windows 11') || lowerOs.includes('macos')) {
    return 'workstation';
  }
  return 'unknown';
}

export function parseNmapXml(xmlContent: string): { devices: NetworkDevice[]; subnetLabel: string } {
  const trimmed = xmlContent.trim();
  if (!trimmed.includes('<nmaprun') && !trimmed.includes('<host')) {
    throw new Error("Format XML Nmap invalide : balise <nmaprun> ou <host> introuvable.");
  }

  const hostBlocks = trimmed.match(/<host\b[^>]*>[\s\S]*?<\/host>/gi) ?? [];
  if (hostBlocks.length === 0) {
    throw new Error("Aucun hôte (<host>) détecté dans le fichier XML Nmap.");
  }

  const devices: NetworkDevice[] = [];

  hostBlocks.forEach((block, index) => {
    const statusMatch = block.match(/<status\b[^>]*>/i);
    const statusState = statusMatch ? extractAttribute(statusMatch[0], 'state') : 'up';
    if (statusState === 'down') return;

    const addrMatches = block.match(/<address\b[^>]*>/gi) ?? [];
    let ip = '';
    let mac: string | undefined;
    let vendor: string | undefined;

    for (const addrTag of addrMatches) {
      const addrType = extractAttribute(addrTag, 'addrtype');
      const addrVal = extractAttribute(addrTag, 'addr');
      if (addrType === 'ipv4' && addrVal) {
        ip = addrVal;
      } else if (addrType === 'ipv6' && !ip && addrVal) {
        ip = addrVal;
      } else if (addrType === 'mac' && addrVal) {
        mac = addrVal;
        vendor = extractAttribute(addrTag, 'vendor');
      }
    }

    if (!ip) return;

    const hostnameMatch = block.match(/<hostname\b[^>]*>/i);
    const hostname = (hostnameMatch ? extractAttribute(hostnameMatch[0], 'name') : undefined) || `hote-${ip.replace(/\./g, '-')}`;

    const osMatch = block.match(/<osmatch\b[^>]*>/i);
    const os = osMatch ? extractAttribute(osMatch[0], 'name') : undefined;

    const portBlocks = block.match(/<port\b[^>]*>[\s\S]*?<\/port>/gi) ?? [];
    const ports: PortEntry[] = [];

    for (const portBlock of portBlocks) {
      const openTag = portBlock.match(/<port\b[^>]*>/i)?.[0] ?? '';
      const portIdStr = extractAttribute(openTag, 'portid');
      const protoStr = (extractAttribute(openTag, 'protocol') ?? 'tcp').toLowerCase();
      if (!portIdStr) continue;

      const portNum = Number.parseInt(portIdStr, 10);
      if (Number.isNaN(portNum)) continue;

      const stateTag = portBlock.match(/<state\b[^>]*>/i)?.[0] ?? '';
      const rawState = (extractAttribute(stateTag, 'state') ?? 'closed').toLowerCase();
      let state: PortState = 'closed';
      if (rawState === 'open' || rawState === 'open|filtered') state = 'open';
      else if (rawState === 'filtered') state = 'filtered';

      const serviceTag = portBlock.match(/<service\b[^>]*>/i)?.[0] ?? '';
      const service = extractAttribute(serviceTag, 'name') ?? 'unknown';
      const product = extractAttribute(serviceTag, 'product');
      const version = extractAttribute(serviceTag, 'version');
      const extraInfo = extractAttribute(serviceTag, 'extrainfo');
      const tunnel = extractAttribute(serviceTag, 'tunnel');

      const banner = [product, version, extraInfo].filter(Boolean).join(' ').trim() || undefined;
      const protocol: Protocol = protoStr === 'udp' ? 'udp' : 'tcp';

      ports.push({
        port: portNum,
        protocol,
        state,
        service,
        product,
        version,
        banner,
        tlsEnabled: tunnel === 'ssl' || portNum === 443 || service === 'https',
        configNotes: extraInfo,
      });
    }

    const deviceType = inferDeviceType(hostname, os, ports);
    devices.push({
      id: `imported-${index + 1}`,
      ip,
      hostname,
      mac,
      vendor,
      os,
      deviceType,
      isGateway: deviceType === 'gateway' || ip.endsWith('.1') || ip.endsWith('.254'),
      ports,
    });
  });

  if (devices.length === 0) {
    throw new Error("Aucun hôte actif avec une adresse IP valide n'a pu être extrait du XML.");
  }

  const firstIpParts = devices[0].ip.split('.');
  const subnetLabel = firstIpParts.length === 4 ? `${firstIpParts[0]}.${firstIpParts[1]}.${firstIpParts[2]}.0/24` : 'Sous-réseau importé';

  return { devices, subnetLabel };
}

export function parseScanInput(rawInput: string): { devices: NetworkDevice[]; subnetLabel: string } {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('Veuillez coller le contenu d’un export Nmap XML ou JSON.');
  }

  if (trimmed.startsWith('<')) {
    return parseNmapXml(trimmed);
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error('JSON invalide : vérifiez la syntaxe du fichier importé.');
    }

    const rawDevices = Array.isArray(parsed)
      ? parsed
      : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { devices?: unknown }).devices)
        ? (parsed as { devices: unknown[] }).devices
        : null;

    if (!rawDevices || rawDevices.length === 0) {
      throw new Error('Le fichier JSON doit contenir un tableau d’appareils ou une clé "devices" non vide.');
    }

    const devices: NetworkDevice[] = rawDevices.map((item, idx) => {
      const obj = item as Record<string, unknown>;
      const ip = typeof obj.ip === 'string' ? obj.ip : '';
      if (!ip) {
        throw new Error(`Appareil #${idx + 1} : adresse IP manquante.`);
      }
      const hostname = typeof obj.hostname === 'string' && obj.hostname ? obj.hostname : `hote-${ip.replace(/\./g, '-')}`;
      const portsRaw = Array.isArray(obj.ports) ? obj.ports : [];
      const ports: PortEntry[] = portsRaw.map((p) => {
        const po = p as Record<string, unknown>;
        const stateRaw = typeof po.state === 'string' ? po.state.toLowerCase() : 'open';
        const state: PortState = stateRaw === 'closed' || stateRaw === 'filtered' ? stateRaw : 'open';
        const protocol: Protocol = po.protocol === 'udp' ? 'udp' : 'tcp';
        return {
          port: Number(po.port ?? 0),
          protocol,
          state,
          service: typeof po.service === 'string' ? po.service : 'unknown',
          product: typeof po.product === 'string' ? po.product : undefined,
          version: typeof po.version === 'string' ? po.version : undefined,
          banner: typeof po.banner === 'string' ? po.banner : undefined,
          tlsEnabled: typeof po.tlsEnabled === 'boolean' ? po.tlsEnabled : undefined,
          authRequired: typeof po.authRequired === 'boolean' ? po.authRequired : undefined,
          configNotes: typeof po.configNotes === 'string' ? po.configNotes : undefined,
        };
      });

      const os = typeof obj.os === 'string' ? obj.os : undefined;
      return {
        id: typeof obj.id === 'string' ? obj.id : `json-${idx + 1}`,
        ip,
        hostname,
        mac: typeof obj.mac === 'string' ? obj.mac : undefined,
        vendor: typeof obj.vendor === 'string' ? obj.vendor : undefined,
        os,
        deviceType: (typeof obj.deviceType === 'string' ? obj.deviceType : inferDeviceType(hostname, os, ports)) as DeviceType,
        isGateway: Boolean(obj.isGateway),
        ports,
      };
    });

    const firstIpParts = devices[0].ip.split('.');
    const subnetLabel = firstIpParts.length === 4 ? `${firstIpParts[0]}.${firstIpParts[1]}.${firstIpParts[2]}.0/24` : 'Sous-réseau JSON';
    return { devices, subnetLabel };
  }

  throw new Error('Format non reconnu. Importez un fichier Nmap XML (<nmaprun>) ou JSON structuré.');
}
