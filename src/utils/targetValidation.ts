export type TargetScope = 'loopback' | 'private_rfc1918' | 'public';

export interface ValidatedTarget {
  normalizedTarget: string;
  isCidr: boolean;
  prefix: number;
  scope: TargetScope;
  hostIps: string[];
}

const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function parseIpv4ToInt(ip: string): number | null {
  const match = ip.trim().match(IPV4_REGEX);
  if (!match) return null;
  const octets = [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2], 10),
    Number.parseInt(match[3], 10),
    Number.parseInt(match[4], 10),
  ];
  if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
  return (
    ((octets[0] << 24) >>> 0) +
    ((octets[1] << 16) >>> 0) +
    ((octets[2] << 8) >>> 0) +
    (octets[3] >>> 0)
  );
}

export function intToIpv4(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join('.');
}

export function classifyIpv4Scope(ipInt: number): { scope: TargetScope; blockedReason?: string } {
  const first = (ipInt >>> 24) & 0xff;
  const second = (ipInt >>> 16) & 0xff;

  // 0.0.0.0/8 unspecified
  if (first === 0) {
    return { scope: 'public', blockedReason: 'Adresse réseau 0.0.0.0/8 non analysable.' };
  }
  // 169.254.0.0/16 link-local / cloud metadata SSRF guard
  if (first === 169 && second === 254) {
    return {
      scope: 'public',
      blockedReason: 'Les adresses link-local / métadonnées (169.254.0.0/16) sont bloquées par sécurité.',
    };
  }
  // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved/broadcast
  if (first >= 224) {
    return {
      scope: 'public',
      blockedReason: 'Les plages multicast et réservées (224.0.0.0+) ne sont pas des cibles valides.',
    };
  }
  // 127.0.0.0/8 loopback
  if (first === 127) {
    return { scope: 'loopback' };
  }
  // RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  if (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  ) {
    return { scope: 'private_rfc1918' };
  }
  // RFC 6598 CGNAT 100.64.0.0/10
  if (first === 100 && second >= 64 && second <= 127) {
    return { scope: 'private_rfc1918' };
  }

  return { scope: 'public' };
}

export function validateAuthorizedTarget(
  rawTarget: string,
  authorized: boolean
): { ok: true; value: ValidatedTarget } | { ok: false; status: number; error: string } {
  if (!authorized) {
    return {
      ok: false,
      status: 403,
      error: "Confirmation d'autorisation explicite requise avant toute analyse cible.",
    };
  }

  const trimmed = rawTarget.trim();
  if (!trimmed) {
    return {
      ok: false,
      status: 400,
      error: 'Veuillez saisir une adresse IPv4 ou un sous-réseau CIDR (ex. 192.168.1.10 ou 192.168.1.0/24).',
    };
  }

  const parts = trimmed.split('/');
  if (parts.length > 2) {
    return {
      ok: false,
      status: 400,
      error: 'Format cible invalide. Exemple attendu : 192.168.1.10 ou 192.168.1.0/24.',
    };
  }

  const ipInt = parseIpv4ToInt(parts[0]);
  if (ipInt === null) {
    return {
      ok: false,
      status: 400,
      error: 'Adresse IPv4 invalide. Utilisez un format IPv4 standard (ex. 192.168.1.15).',
    };
  }

  let prefix = 32;
  let isCidr = false;
  if (parts.length === 2) {
    isCidr = true;
    if (!/^\d{1,2}$/.test(parts[1])) {
      return { ok: false, status: 400, error: 'Masque CIDR invalide (attendu : /24 à /32).' };
    }
    prefix = Number.parseInt(parts[1], 10);
    if (prefix < 24 || prefix > 32) {
      return {
        ok: false,
        status: 400,
        error: 'Pour éviter la saturation réseau, la plage CIDR est limitée de /24 à /32.',
      };
    }
  }

  const { scope, blockedReason } = classifyIpv4Scope(ipInt);
  if (blockedReason) {
    return { ok: false, status: 400, error: blockedReason };
  }

  if (prefix === 32) {
    const ipStr = intToIpv4(ipInt);
    return {
      ok: true,
      value: {
        normalizedTarget: isCidr ? `${ipStr}/32` : ipStr,
        isCidr,
        prefix: 32,
        scope,
        hostIps: [ipStr],
      },
    };
  }

  const hostBits = 32 - prefix;
  const mask = (0xffffffff << hostBits) >>> 0;
  const networkInt = (ipInt & mask) >>> 0;
  const totalAddresses = 1 << hostBits;
  const hostIps: string[] = [];

  if (prefix === 31) {
    hostIps.push(intToIpv4(networkInt), intToIpv4((networkInt + 1) >>> 0));
  } else {
    // Skip network (.0) and broadcast (.255), cap probe list at 32 addresses for fast bounded checks
    const maxHosts = Math.min(totalAddresses - 2, 32);
    for (let offset = 1; offset <= maxHosts; offset += 1) {
      hostIps.push(intToIpv4((networkInt + offset) >>> 0));
    }
  }

  return {
    ok: true,
    value: {
      normalizedTarget: `${intToIpv4(networkInt)}/${prefix}`,
      isCidr: true,
      prefix,
      scope,
      hostIps,
    },
  };
}

export function enforceHttpsUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  if (!trimmed) return 'https://localhost:3000';
  if (trimmed.startsWith('http://')) {
    return `https://${trimmed.slice('http://'.length)}`;
  }
  if (!trimmed.startsWith('https://')) {
    return `https://${trimmed}`;
  }
  return trimmed;
}
