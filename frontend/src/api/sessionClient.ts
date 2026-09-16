import {
  ensureSodium,
  type IdentityKeyPair,
} from '../crypto/identity';
import {
  sealGroupMessage,
  sealMessageEnvelope,
  type HybridEnvelope,
  type InnerMessage,
} from '../crypto/envelope';
import {
  conversationKeyForGroup,
  resolveGroupKey,
  type DeleteMessageNotice,
  type GroupControlMessage,
  type GroupMeta,
} from '../crypto/groupSecurity';
import { buildRetrieveParams } from '../network/sessionAuth';
import {
  ensureSnodePoolReady,
  retrieveEncryptedMessages,
  storeEncryptedMessage,
  tryParseEnvelope,
  DEFAULT_TTL_MS,
  type StoreReceipt,
} from '../network/sessionClient';

type Sodium = Awaited<ReturnType<typeof ensureSodium>>;

/**
 * Legacy swarm-aware retrieve via Gateway Bridge only (no browser→SNode TLS).
 */
async function pollViaRelay(
  mySessionId: string,
  myPrivateKey: Uint8Array,
): Promise<HybridEnvelope[]> {
  const s = await ensureSodium();
  const auth = await buildRetrieveParams({
    sessionId: mySessionId,
    ed25519SecretKey: myPrivateKey,
    lastHash: '',
  });

  const response = await fetch('/api/relay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      onionPacket: {
        method: 'retrieve',
        ...auth.params,
      },
      headers: auth.headers,
    }),
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    throw new Error(body?.error ?? `Relay error ${response.status}`);
  }

  return extractEnvelopes(await response.json(), s);
}

function extractEnvelopes(payload: unknown, s: Sodium): HybridEnvelope[] {
  const envelopes: HybridEnvelope[] = [];

  const visit = (node: unknown): void => {
    if (node === null || node === undefined) {
      return;
    }

    const direct = tryParseEnvelope(node, s);
    if (direct) {
      envelopes.push(direct);
      return;
    }

    if (Array.isArray(node)) {
      for (const item of node) {
        visit(item);
      }
      return;
    }

    if (typeof node === 'object') {
      const record = node as Record<string, unknown>;
      if (typeof record.data === 'string') {
        const fromData = tryParseEnvelope(record.data, s);
        if (fromData) {
          envelopes.push(fromData);
          return;
        }
      }
      for (const key of ['messages', 'result', 'body', 'data'] as const) {
        if (key in record) {
          visit(record[key]);
        }
      }
    }
  };

  visit(payload);
  return envelopes;
}

/**
 * Store envelope on the recipient's real Session swarm (no mock relay).
 * Requires a real SNode receipt hash before resolving.
 */
export async function dispatchEnvelope(
  recipientSessionId: string,
  envelope: HybridEnvelope,
  ttlMs: number = DEFAULT_TTL_MS,
  signer?: { sessionId: string; secretKey: Uint8Array },
): Promise<{
  status: 'OK';
  via: 'snode';
  hash: string;
  receipts: StoreReceipt[];
  raw: unknown;
}> {
  await ensureSnodePoolReady();
  const result = await storeEncryptedMessage(recipientSessionId, envelope, {
    ttlMs,
    replicas: 2,
    signerSecretKey: signer?.secretKey,
    signerSessionId: signer?.sessionId,
  });
  if (!result.hash || result.accepted < 1 || result.receipts.length === 0) {
    throw new Error(
      'Store sem recibo/hash do SNode — mensagem não confirmada na rede',
    );
  }
  return {
    status: 'OK',
    via: 'snode',
    hash: result.hash,
    receipts: result.receipts,
    raw: result.receipts[0]?.raw,
  };
}

/**
 * Retrieve inbox from the local user's swarm.
 * Falls back to the local gateway only when SNode bootstrap is unavailable
 * (e.g. offline seed access during early local bring-up).
 */
export async function pollInbox(
  mySessionId: string,
  myPrivateKey: Uint8Array,
): Promise<HybridEnvelope[]> {
  try {
    await ensureSnodePoolReady();
    const rows = await retrieveEncryptedMessages(mySessionId, myPrivateKey);
    const envelopes: HybridEnvelope[] = [];
    for (const row of rows) {
      if (row.envelope) {
        envelopes.push(row.envelope);
      }
    }
    return envelopes;
  } catch {
    return pollViaRelay(mySessionId, myPrivateKey);
  }
}

/**
 * Fan-out a closed-group message: encrypt with group key, then seal to each member inbox.
 */
export async function dispatchGroupMessage(
  groupMeta: GroupMeta,
  innerMessage: InnerMessage,
  myKeyPair: IdentityKeyPair,
): Promise<void> {
  const s = await ensureSodium();
  const groupKey = await resolveGroupKey(groupMeta.groupKeyHex);

  try {
    const sealed = await sealGroupMessage(
      {
        ...innerMessage,
        groupId: groupMeta.groupId,
      },
      groupKey,
    );

    const mySessionId = `05${s.to_hex(myKeyPair.publicKey)}`;
    const recipients = groupMeta.members.filter((id) => id !== mySessionId);

    for (const memberId of recipients) {
      const carrier: InnerMessage = {
        id: innerMessage.id,
        senderSessionId: innerMessage.senderSessionId,
        text: innerMessage.text || `[grupo:${groupMeta.name}]`,
        sentAt: innerMessage.sentAt,
        viewPolicy: 'PERMANENT',
        groupId: groupMeta.groupId,
        groupCiphertext: sealed.ciphertext,
        groupNonce: sealed.nonce,
      };
      if (typeof innerMessage.ttlDays === 'number') {
        carrier.ttlDays = innerMessage.ttlDays;
      }

      const envelope = await sealMessageEnvelope(carrier, memberId);
      await dispatchEnvelope(memberId, envelope, undefined, {
        sessionId: mySessionId,
        secretKey: myKeyPair.privateKey,
      });
    }
  } finally {
    s.memzero(groupKey);
  }
}

/**
 * Deliver a membership/key control message sealed to a specific member inbox.
 */
export async function dispatchGroupControl(
  targetSessionId: string,
  controlPayload: GroupControlMessage,
  myKeyPair: IdentityKeyPair,
): Promise<void> {
  const s = await ensureSodium();
  const senderSessionId = `05${s.to_hex(myKeyPair.publicKey)}`;

  const carrier: InnerMessage = {
    id: `${controlPayload.type}-${controlPayload.groupId}-${Date.now()}`,
    senderSessionId,
    text: `[controle:${controlPayload.type}]`,
    sentAt: controlPayload.timestamp || Date.now(),
    viewPolicy: 'PERMANENT',
    groupId: controlPayload.groupId,
    control: controlPayload,
  };

  const envelope = await sealMessageEnvelope(carrier, targetSessionId);
  await dispatchEnvelope(targetSessionId, envelope, undefined, {
    sessionId: senderSessionId,
    secretKey: myKeyPair.privateKey,
  });
}

/**
 * Fan-out a control message to every active group member except the sender
 * (and any explicit exclusions).
 */
export async function broadcastGroupControl(
  meta: GroupMeta,
  controlPayload: GroupControlMessage,
  myKeyPair: IdentityKeyPair,
  options?: { excludeSessionIds?: string[] },
): Promise<void> {
  const s = await ensureSodium();
  const mySessionId = `05${s.to_hex(myKeyPair.publicKey)}`;
  const excluded = new Set(options?.excludeSessionIds ?? []);

  for (const memberId of meta.members) {
    if (memberId === mySessionId || excluded.has(memberId)) {
      continue;
    }
    await dispatchGroupControl(memberId, controlPayload, myKeyPair);
  }
}

/**
 * Dispatch a silent DELETE_FOR_ALL notice to 1:1 peer or all active group members.
 * Caller is responsible for the local physical wipe.
 */
export async function dispatchDeleteForAll(
  targetMessageId: string,
  conversationWith: string,
  isGroup: boolean,
  myKeyPair: IdentityKeyPair,
  groupMeta?: GroupMeta,
): Promise<void> {
  const s = await ensureSodium();
  const mySessionId = `05${s.to_hex(myKeyPair.publicKey)}`;
  const timestamp = Date.now();

  const notice: DeleteMessageNotice = {
    type: 'DELETE_FOR_ALL',
    targetMessageId,
    deletedBy: mySessionId,
    timestamp,
  };
  if (isGroup && groupMeta) {
    notice.groupId = groupMeta.groupId;
  }

  const carrier: InnerMessage = {
    id: `delete-${targetMessageId}-${timestamp}`,
    senderSessionId: mySessionId,
    text: '',
    sentAt: timestamp,
    viewPolicy: 'PERMANENT',
    deleteNotice: notice,
  };
  if (notice.groupId) {
    carrier.groupId = notice.groupId;
  }

  if (isGroup && groupMeta) {
    for (const memberId of groupMeta.members) {
      if (memberId === mySessionId) {
        continue;
      }
      const envelope = await sealMessageEnvelope(carrier, memberId);
      await dispatchEnvelope(memberId, envelope, undefined, {
        sessionId: mySessionId,
        secretKey: myKeyPair.privateKey,
      });
    }
    return;
  }

  const peer = conversationWith;
  if (!peer || peer === mySessionId) {
    return;
  }
  const envelope = await sealMessageEnvelope(carrier, peer);
  await dispatchEnvelope(peer, envelope, undefined, {
    sessionId: mySessionId,
    secretKey: myKeyPair.privateKey,
  });
}

export { conversationKeyForGroup };
