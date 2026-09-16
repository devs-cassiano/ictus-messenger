/**
 * Public Session / Oxen bootstrap endpoints (HTTPS seeds + known storage ports).
 */

export interface SeedJsonRpc {
  /** Full JSON-RPC URL used for get_service_nodes. */
  url: string;
  label: string;
}

export interface SeedNode {
  host: string;
  port: number;
}

/** Official Session seed JSON-RPC endpoints (seed3 first — more reachable). */
export const SEED_JSON_RPC: readonly SeedJsonRpc[] = [
  { url: 'https://seed3.getsession.org/json_rpc', label: 'seed3.getsession.org' },
  { url: 'https://seed1.getsession.org/json_rpc', label: 'seed1.getsession.org' },
  { url: 'https://seed2.getsession.org/json_rpc', label: 'seed2.getsession.org' },
];

/** Legacy IP:port seed entries (storage / oxend HTTPS). */
export const SEED_NODES: SeedNode[] = [
  { host: '116.202.110.147', port: 22020 },
  { host: '168.119.118.172', port: 22020 },
  { host: '135.181.238.169', port: 22020 },
];
