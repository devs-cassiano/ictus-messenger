/**
 * SSRF defenses for Gateway Bridge upstream targets.
 * Only HTTPS Session seed/storage RPC endpoints may be reached.
 */

import { Address4, Address6 } from 'ip-address';

export const SSRF_BLOCKED_MESSAGE =
  'Destino inválido ou bloqueado por política de segurança';

const ALLOWED_PATH_SUFFIXES = ['/storage_rpc/v1', '/json_rpc'] as const;

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
  // Explicit CGNAT / documentation / reserved extras beyond isPrivate()
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
  if (Address4.isValid(host)) {
    return isBlockedIpv4(host);
  }
  if (Address6.isValid(host)) {
    return isBlockedIpv6(host);
  }
  // Public DNS hostnames (Session seeds) are allowed.
  return false;
}

function pathnameAllowed(pathname: string): boolean {
  const normalized =
    pathname.length > 1 && pathname.endsWith('/')
      ? pathname.slice(0, -1)
      : pathname;
  return ALLOWED_PATH_SUFFIXES.some(
    (suffix) => normalized === suffix || normalized.endsWith(suffix),
  );
}

/**
 * Returns true when `targetUrl` is a safe Session upstream HTTPS endpoint.
 */
export function validateTargetUrl(targetUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') {
    return false;
  }
  if (parsed.username || parsed.password) {
    return false;
  }
  if (!pathnameAllowed(parsed.pathname)) {
    return false;
  }
  if (isBlockedHost(parsed.hostname)) {
    return false;
  }
  return true;
}
