import { ensureSodium } from './identity';

export interface GroupMeta {
  groupId: string;
  name: string;
  admins: string[];
  members: string[];
  groupKeyHex: string;
  keyVersion: number;
}

export type GroupControlType =
  | 'INVITE'
  | 'MEMBER_ADDED'
  | 'MEMBER_REMOVED'
  | 'KEY_ROTATION'
  | 'NAME_CHANGED'
  | 'ADMINS_UPDATED';

export interface GroupControlMessage {
  type: GroupControlType;
  groupId: string;
  updatedMeta: GroupMeta;
  triggeredBy: string;
  timestamp: number;
}

/** Silent wipe order used in 1:1 and closed groups (no tombstone left). */
export interface DeleteMessageNotice {
  type: 'DELETE_FOR_ALL';
  targetMessageId: string;
  deletedBy: string;
  timestamp: number;
  groupId?: string;
}

export function isDeleteMessageNotice(
  value: unknown,
): value is DeleteMessageNotice {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    record.type === 'DELETE_FOR_ALL' &&
    typeof record.targetMessageId === 'string' &&
    typeof record.deletedBy === 'string' &&
    typeof record.timestamp === 'number'
  );
}

const CONTROL_TYPES: ReadonlySet<string> = new Set([
  'INVITE',
  'MEMBER_ADDED',
  'MEMBER_REMOVED',
  'KEY_ROTATION',
  'NAME_CHANGED',
  'ADMINS_UPDATED',
]);

export function canManageGroup(meta: GroupMeta, sessionId: string): boolean {
  return meta.admins.includes(sessionId);
}

export function renameGroup(
  meta: GroupMeta,
  newName: string,
  requesterSessionId: string,
): GroupMeta {
  if (!canManageGroup(meta, requesterSessionId)) {
    throw new Error('Apenas administradores podem renomear o grupo.');
  }
  const name = newName.trim();
  if (!name) {
    throw new Error('Nome do grupo não pode ser vazio.');
  }
  return { ...meta, name };
}

export function promoteToAdmin(
  meta: GroupMeta,
  targetSessionId: string,
  requesterSessionId: string,
): GroupMeta {
  if (!canManageGroup(meta, requesterSessionId)) {
    throw new Error('Apenas administradores podem promover membros.');
  }
  if (!meta.members.includes(targetSessionId)) {
    throw new Error('O alvo precisa ser membro do grupo.');
  }
  if (meta.admins.includes(targetSessionId)) {
    return meta;
  }
  return {
    ...meta,
    admins: [...meta.admins, targetSessionId],
  };
}

export function demoteAdmin(
  meta: GroupMeta,
  targetSessionId: string,
  requesterSessionId: string,
): GroupMeta {
  if (!canManageGroup(meta, requesterSessionId)) {
    throw new Error('Apenas administradores podem rebaixar admins.');
  }
  if (!meta.admins.includes(targetSessionId)) {
    return meta;
  }
  if (meta.admins.length <= 1) {
    throw new Error('O grupo deve manter ao menos um administrador.');
  }
  return {
    ...meta,
    admins: meta.admins.filter((id) => id !== targetSessionId),
  };
}

/**
 * Create a closed group with a fresh symmetric key (32 bytes).
 * Creator becomes the initial sole admin.
 */
export async function createGroup(
  name: string,
  mySessionId: string,
  initialMembers: string[],
): Promise<GroupMeta> {
  const s = await ensureSodium();
  const groupId = s.to_hex(s.randombytes_buf(16));
  const groupKey = s.crypto_secretbox_keygen();

  const members = Array.from(
    new Set(
      [mySessionId, ...initialMembers]
        .map((id) => id.trim())
        .filter((id) => id.length > 0),
    ),
  );

  const meta: GroupMeta = {
    groupId,
    name: name.trim() || 'Grupo',
    admins: [mySessionId],
    members,
    groupKeyHex: s.to_hex(groupKey),
    keyVersion: 1,
  };

  s.memzero(groupKey);
  return meta;
}

/**
 * Remove a member and rotate the group key (backward secrecy).
 * Also drops the member from admins; refuses if that would leave zero admins.
 */
export async function rotateGroupKey(
  meta: GroupMeta,
  removedMemberSessionId: string,
): Promise<GroupMeta> {
  const s = await ensureSodium();

  const admins = meta.admins.filter((id) => id !== removedMemberSessionId);
  if (admins.length === 0) {
    throw new Error(
      'Não é possível remover o único administrador do grupo.',
    );
  }

  const groupKey = s.crypto_secretbox_keygen();
  const members = meta.members.filter((id) => id !== removedMemberSessionId);

  const updated: GroupMeta = {
    ...meta,
    members,
    admins,
    groupKeyHex: s.to_hex(groupKey),
    keyVersion: meta.keyVersion + 1,
  };

  s.memzero(groupKey);
  return updated;
}

export async function resolveGroupKey(groupKeyHex: string): Promise<Uint8Array> {
  const s = await ensureSodium();
  return s.from_hex(groupKeyHex);
}

function isGroupMeta(value: unknown): value is GroupMeta {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.groupId === 'string' &&
    typeof record.name === 'string' &&
    Array.isArray(record.members) &&
    Array.isArray(record.admins) &&
    typeof record.groupKeyHex === 'string' &&
    typeof record.keyVersion === 'number'
  );
}

export function isGroupControlMessage(
  value: unknown,
): value is GroupControlMessage {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.type === 'string' &&
    CONTROL_TYPES.has(record.type) &&
    typeof record.groupId === 'string' &&
    isGroupMeta(record.updatedMeta) &&
    typeof record.triggeredBy === 'string' &&
    typeof record.timestamp === 'number'
  );
}

/**
 * Decide whether an inbound control message should be applied.
 * NAME_CHANGED / ADMINS_UPDATED require triggeredBy to be a current local admin.
 */
export function shouldAcceptGroupControl(
  localMeta: GroupMeta | null,
  control: GroupControlMessage,
): boolean {
  if (control.type === 'INVITE' && !localMeta) {
    return isGroupMeta(control.updatedMeta);
  }

  if (!localMeta) {
    // First sight of group via MEMBER_ADDED / KEY_ROTATION etc.
    return control.type === 'INVITE' || control.type === 'MEMBER_ADDED';
  }

  if (control.groupId !== localMeta.groupId) {
    return false;
  }

  if (
    control.type === 'NAME_CHANGED' ||
    control.type === 'ADMINS_UPDATED'
  ) {
    return canManageGroup(localMeta, control.triggeredBy);
  }

  // Membership / key events must also come from a known admin when we already have meta.
  return canManageGroup(localMeta, control.triggeredBy);
}

export function buildGroupControl(
  type: GroupControlType,
  updatedMeta: GroupMeta,
  triggeredBy: string,
): GroupControlMessage {
  return {
    type,
    groupId: updatedMeta.groupId,
    updatedMeta,
    triggeredBy,
    timestamp: Date.now(),
  };
}

export function conversationKeyForGroup(groupId: string): string {
  return `group:${groupId}`;
}
