/**
 * SSRF defenses for Gateway Bridge upstream targets.
 * Allows Session seeds / public SNodes (HTTPS + storage_rpc|json_rpc) while
 * blocking private, loopback, link-local and cloud-metadata destinations.
 */

import { Address4, Address6 } from 'ip-address';

export const SSRF_BLOCKED_MESSAGE =
  'Destino inválido ou bloqueado por política de segurança';

/** Well-known Session / Oxen public DNS suffixes (seeds & infra). */
const ALLOWED_HOST_SUFFIXES = [
  '.getsession.org',
  '.oxen.io',
  '.oxen.rocks',
  '.loki',
] as const;

const ALLOWED_EXACT_HOSTS = new Set([
  'getsession.org',
  'seed1.getsession.org',
  'seed2.getsession.org',
  'seed3.getsession.org',
]);

/** Common Session SNode / seed HTTPS ports (plus standard web). */
const ALLOWED_PORTS = new Set<number>([443, 80, 22020, 22021, 22022, 22023, 22024, 22025]);

function hostnameIsBlockedName(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  return (
    h === 'localhost' ||
    h === 'localhost.localdomain' ||
    h.endsWith('.localhost') ||
    h === 'metadata.google.internal' ||
    h === 'metadata'
  );
}

function isAllowedSessionHostname(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (ALLOWED_EXACT_HOSTS.has(h)) {
    return true;
  }
  return ALLOWED_HOST_SUFFIXES.some(
    (suffix) => h === suffix.slice(1) || h.endsWith(suffix),
  );
}

function isBlockedIpv4(ip: string): boolean {
  let addr: Address4;
  try {
    addr = new Address4(ip);
  } catch {
    return true;
  }
  if (ip === '169.254.169.254') {
    return true;
  }
  if (
    addr.isLoopback() ||
    addr.isPrivate() ||
    addr.isLinkLocal() ||
    addr.isMulticast()
  ) {
    return true;
  }
  const extraCidrs = [
    '0.0.0.0/8',
    '100.64.0.0/10',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '240.0.0.0/4',
  ] as const;
  for (const cidr of extraCidrs) {
    try {
      if (addr.isInSubnet(new Address4(cidr))) {
        return true;
      }
    } catch {
      // ignore
    }
  }
  return false;
}

function isBlockedIpv6(ip: string): boolean {
  let addr: Address6;
  try {
    addr = new Address6(ip);
  } catch {
    return true;
  }
  if (addr.isLoopback() || addr.isLinkLocal() || addr.isULA()) {
    return true;
  }
  if (addr.is4()) {
    try {
      const v4 = addr.to4();
      if (isBlockedIpv4(v4.correctForm())) {
        return true;
      }
    } catch {
      return true;
    }
  }
  return false;
}

function isBlockedHost(host: string): boolean {
  if (hostnameIsBlockedName(host)) {
    return true;
  }
  // Trusted Session DNS names skip IP classification.
  if (isAllowedSessionHostname(host)) {
    return false;
  }
  if (Address4.isValid(host)) {
    return isBlockedIpv4(host);
  }
  if (Address6.isValid(host)) {
    return isBlockedIpv6(host);
  }
  // Other public DNS hostnames (SNode CNAMEs, etc.) are allowed.
  return false;
}

function pathnameAllowed(pathname: string): boolean {
  let normalized = pathname.trim();
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  const lower = normalized.toLowerCase();
  return (
    lower === '/storage_rpc/v1' ||
    lower === '/json_rpc' ||
    lower.endsWith('/storage_rpc/v1') ||
    lower.endsWith('/json_rpc')
  );
}

function portAllowed(parsed: URL): boolean {
  const raw = parsed.port;
  if (!raw) {
    // Default https → 443, http → 80
    return true;
  }
  const port = Number(raw);
  if (!Number.isFinite(port)) {
    return false;
  }
  if (ALLOWED_PORTS.has(port)) {
    return true;
  }
  // Session / Oxen storage nodes commonly use 22020–22099
  if (port >= 22020 && port <= 22099) {
    return true;
  }
  return false;
}

/**
 * Returns true when `targetUrl` is a safe Session upstream HTTPS endpoint.
 */
export function validateTargetUrl(targetUrl: string): boolean {
  if (typeof targetUrl !== 'string') {
    return false;
  }
  const trimmed = targetUrl.trim();
  if (!trimmed) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return false;
  }

  // Session swarm / seeds are HTTPS-only from the browser contract.
  if (parsed.protocol !== 'https:') {
    return false;
  }
  if (parsed.username || parsed.password) {
    return false;
  }
  if (!pathnameAllowed(parsed.pathname)) {
    return false;
  }
  if (!portAllowed(parsed)) {
    return false;
  }
  if (isBlockedHost(parsed.hostname)) {
    return false;
  }
  return true;
}
