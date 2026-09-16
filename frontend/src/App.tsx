import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  dispatchDeleteForAll,
  dispatchEnvelope,
  dispatchGroupControl,
  dispatchGroupMessage,
  broadcastGroupControl,
  pollInbox,
} from './api/sessionClient';
import { resetNetworkSession, logEnvelopeDecryptResult } from './network/sessionClient';
import { sessionNetLog, truncateId } from './network/sessionNetLog';
import { AuthLockPanel } from './components/AuthLockPanel';
import { IdentityShareModal } from './components/IdentityShareModal';
import { LanguageSelector } from './components/LanguageSelector';
import { PinVaultModal } from './components/PinVaultModal';
import { QrScannerModal } from './components/QrScannerModal';
import { SafeAttachment, createAttachmentBlobUrl } from './components/SafeAttachment';
import { SafeMessageText } from './components/SafeMessageText';
import { ShowRecoveryPhraseModal } from './components/ShowRecoveryPhraseModal';
import {
  IconCamera,
  IconCheck,
  IconChevronDown,
  IconChevronLeft,
  IconClock,
  IconCopy,
  IconDownload,
  IconEye,
  IconFile,
  IconFlame,
  IconImage,
  IconInfinity,
  IconLockExport,
  IconLockImport,
  IconLogOut,
  IconMessagePlus,
  IconMoreHorizontal,
  IconPanic,
  IconPaperclip,
  IconPanelLeftClose,
  IconPanelLeftOpen,
  IconPencil,
  IconQrCode,
  IconRefresh,
  IconSend,
  IconShield,
  IconTrash,
  IconUsersPlus,
  IconX,
} from './components/ui/Icons';
import {
  openGroupMessage,
  openMessageEnvelope,
  sealMessageEnvelope,
  type InnerMessage,
  type MessageAttachment,
  type ViewPolicy,
} from './crypto/envelope';
import {
  buildTextPreview,
  isImageMime,
  MAX_ATTACHMENT_BYTES,
  prepareOutgoingFile,
} from './crypto/fileSecurity';
import {
  buildGroupControl,
  canManageGroup,
  conversationKeyForGroup,
  createGroup,
  demoteAdmin,
  promoteToAdmin,
  renameGroup,
  resolveGroupKey,
  rotateGroupKey,
  shouldAcceptGroupControl,
  type GroupControlMessage,
  type GroupMeta,
} from './crypto/groupSecurity';
import {
  extractSessionId,
  ensureSodium,
  isValidSessionId,
  type IdentityKeyPair,
} from './crypto/identity';
import { sanitizeSessionId } from './utils/validators';
import { sanitizePlainMessageText } from './utils/sanitizeMessage';
import {
  clearFaviconNotifications,
  setDocumentUnreadTitle,
  setFaviconBadge,
} from './utils/favicon';
import {
  downloadVaultFile,
  openConversationVault,
  parseVaultFileEnvelope,
  sealConversationVault,
  VaultImportError,
} from './crypto/vaultExport';
import {
  clearTabSession,
  loadTabSession,
  saveTabSession,
} from './session/tabSession';
import { scheduleClipboardClear } from './crypto/clipboardGuard';
import {
  consumeMessageView,
  deleteConversation,
  deleteGroup,
  deleteMessageForAll,
  deleteMessageForMe,
  getConversationList,
  getGroupMeta,
  getMessages,
  handleRemoteDeleteNotice,
  purgeInconsistentVault,
  mergeImportedMessages,
  purgeExpiredMessages,
  registerMessageBlobUrl,
  remainingViews,
  revokeAllMessageBlobUrls,
  saveGroupMeta,
  saveIncomingOrOutgoingMessage,
  updateMessageDeliveryStatus,
  triggerPanicPurge,
  hasExistingVault,
  vaultHasMnemonic,
  type ConversationPreview,
  type DecryptedMessage,
} from './storage/db';
import './App.css';

type AppPhase = 'locked' | 'chat';
type TtlOption = 0 | 1 | 7 | 30;

interface MediaModalState {
  kind: 'image' | 'text';
  messageId: string;
  blobUrl?: string;
  downloadName?: string;
  text?: string;
  /** When true, closing the modal consumes a limited view. */
  ephemeral?: boolean;
}

function newMessageId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function shortenSessionId(id: string): string {
  if (id.length <= 16) {
    return id;
  }
  return `${id.slice(0, 10)}…${id.slice(-6)}`;
}

function conversationDisplayName(
  c: {
    peerSessionId: string;
    isGroup?: boolean;
    groupName?: string;
  },
  defaultGroupName: string,
): string {
  if (c.isGroup) {
    return c.groupName?.trim() || defaultGroupName;
  }
  return shortenSessionId(c.peerSessionId);
}

/** Legacy PT/EN captions plus the active locale label for attachment-only rows. */
function isDefaultAttachmentCaption(text: string, localized: string): boolean {
  return (
    text === localized ||
    text === 'Anexo' ||
    text === 'Attachment' ||
    text.startsWith('Anexo')
  );
}

function conversationInitials(c: {
  peerSessionId: string;
  isGroup?: boolean;
  groupName?: string;
}): string {
  if (c.isGroup) {
    const name = c.groupName?.trim() || 'G';
    const parts = name.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[0]![0] ?? ''}${parts[1]![0] ?? ''}`.toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }
  return c.peerSessionId.slice(2, 4).toUpperCase() || '??';
}

const SIDEBAR_COLLAPSED_KEY = 'ictus.sidebarCollapsed';

function readSidebarCollapsed(): boolean {
  try {
    return sessionStorage.getItem(SIDEBAR_COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}

function writeSidebarCollapsed(collapsed: boolean): void {
  try {
    sessionStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0');
  } catch {
    // ignore quota / private mode
  }
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function parseSessionIds(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of raw.split(/[\s,;]+/)) {
    const id = sanitizeSessionId(part);
    if (id && !seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

async function fileToAttachment(
  file: File,
  fileTooLargeMessage: string,
): Promise<MessageAttachment> {
  if (file.size > MAX_ATTACHMENT_BYTES) {
    throw new Error(fileTooLargeMessage);
  }

  const s = await ensureSodium();
  const prepared = await prepareOutgoingFile(file);

  const attachment: MessageAttachment = {
    fileName: prepared.fileName,
    mimeType: prepared.mimeType,
    dataBase64: s.to_base64(prepared.buffer),
    size: prepared.buffer.byteLength,
  };

  const preview = buildTextPreview(prepared.buffer, prepared.mimeType);
  if (preview !== undefined) {
    attachment.textPreview = preview;
  }

  return attachment;
}

export default function App() {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<AppPhase>('locked');
  const [busy, setBusy] = useState(false);
  const [, setError] = useState<string | null>(null);
  const [showRecoveryPhrase, setShowRecoveryPhrase] = useState(false);
  const [canShowRecovery, setCanShowRecovery] = useState(false);

  const [sessionId, setSessionId] = useState('');
  const [keyPair, setKeyPair] = useState<IdentityKeyPair | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);

  const [conversations, setConversations] = useState<ConversationPreview[]>([]);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeGroup, setActiveGroup] = useState<GroupMeta | null>(null);
  const [newPeerInput, setNewPeerInput] = useState('');
  const [showNewPeer, setShowNewPeer] = useState(false);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [groupNameInput, setGroupNameInput] = useState('');
  const [groupMembersInput, setGroupMembersInput] = useState('');
  const [showMembersPanel, setShowMembersPanel] = useState(false);
  const [inviteMemberInput, setInviteMemberInput] = useState('');
  const [editingName, setEditingName] = useState(false);
  const [renameInput, setRenameInput] = useState('');

  const [draft, setDraft] = useState('');
  const [ttlDays, setTtlDays] = useState<TtlOption>(0);
  const [viewPolicy, setViewPolicy] = useState<ViewPolicy>('PERMANENT');
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [copied, setCopied] = useState(false);
  const [pendingFile, setPendingFile] = useState<File | null>(null);
  const [mediaModal, setMediaModal] = useState<MediaModalState | null>(null);
  const [menuMessageId, setMenuMessageId] = useState<string | null>(null);
  const [showIdentityShare, setShowIdentityShare] = useState(false);
  const [showQrScanner, setShowQrScanner] = useState(false);
  const [chatMenuOpen, setChatMenuOpen] = useState(false);
  const [vaultModal, setVaultModal] = useState<'export' | 'import' | null>(
    null,
  );
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [pendingImportText, setPendingImportText] = useState<string | null>(
    null,
  );
  const [pendingImportFile, setPendingImportFile] = useState<File | null>(null);
  const [panicClickCount, setPanicClickCount] = useState(0);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(
    readSidebarCollapsed,
  );
  const vaultFileInputRef = useRef<HTMLInputElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const panicClickCountRef = useRef(0);
  const panicResetTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  const vaultKeyRef = useRef<Uint8Array | null>(null);
  const keyPairRef = useRef<IdentityKeyPair | null>(null);
  const sessionIdRef = useRef('');
  const activePeerRef = useRef<string | null>(null);
  const syncingRef = useRef(false);

  const scrollContainerRef = useRef<HTMLElement | null>(null);
  const bottomAnchorRef = useRef<HTMLDivElement | null>(null);
  const prevMessagesLengthRef = useRef(0);
  const isAtBottomRef = useRef(true);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [unreadCount, setUnreadCount] = useState(0);

  function vaultImportErrorMessage(err: unknown): string {
    if (err instanceof VaultImportError) {
      switch (err.code) {
        case 'empty':
          return t('backup.emptyFile');
        case 'not_json':
          return t('backup.notJson');
        case 'bad_envelope':
        case 'bad_crypto_fields':
          return t('backup.badEnvelope');
        case 'bad_pin':
          return t('backup.badPin');
        case 'bad_signature':
          return t('backup.badSignature');
        case 'not_participant':
          return t('backup.notParticipant');
        default:
          return err.message || t('backup.importFail');
      }
    }
    if (err instanceof Error) {
      return err.message;
    }
    return t('backup.importFail');
  }

  useEffect(() => {
    vaultKeyRef.current = vaultKey;
  }, [vaultKey]);

  useEffect(() => {
    keyPairRef.current = keyPair;
  }, [keyPair]);

  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);

  useEffect(() => {
    isAtBottomRef.current = isAtBottom;
  }, [isAtBottom]);

  const scrollToBottom = useCallback((behavior: ScrollBehavior = 'smooth') => {
    bottomAnchorRef.current?.scrollIntoView({ behavior, block: 'end' });
  }, []);

  const handleHistoryScroll = useCallback(() => {
    const container = scrollContainerRef.current;
    if (!container) {
      return;
    }
    const threshold = 120;
    const isClose =
      container.scrollHeight - container.scrollTop - container.clientHeight <=
      threshold;
    if (isClose) {
      setIsAtBottom(true);
      setUnreadCount(0);
    } else {
      setIsAtBottom(false);
    }
  }, []);

  // Contact switch / history load: jump to latest instantly.
  useEffect(() => {
    setUnreadCount(0);
    setIsAtBottom(true);
    isAtBottomRef.current = true;
    prevMessagesLengthRef.current = 0;
    const id = window.requestAnimationFrame(() => {
      scrollToBottom('auto');
    });
    return () => {
      window.cancelAnimationFrame(id);
    };
  }, [activePeer, scrollToBottom]);

  // Sticky scroll + unread badge when the message list grows.
  useEffect(() => {
    const prevLen = prevMessagesLengthRef.current;
    const nextLen = messages.length;

    if (nextLen === 0) {
      prevMessagesLengthRef.current = 0;
      return;
    }

    // First paint for this conversation (or after peer switch reset).
    if (prevLen === 0) {
      prevMessagesLengthRef.current = nextLen;
      const id = window.requestAnimationFrame(() => {
        scrollToBottom('auto');
        setIsAtBottom(true);
        setUnreadCount(0);
      });
      return () => {
        window.cancelAnimationFrame(id);
      };
    }

    if (nextLen <= prevLen) {
      prevMessagesLengthRef.current = nextLen;
      return;
    }

    const added = messages.slice(prevLen);
    const hasOwn = added.some((m) => m.senderSessionId === sessionId);
    const delta = nextLen - prevLen;

    if (hasOwn) {
      scrollToBottom('smooth');
      setIsAtBottom(true);
      setUnreadCount(0);
    } else if (isAtBottomRef.current) {
      scrollToBottom('smooth');
    } else {
      setUnreadCount((prev) => prev + delta);
    }

    prevMessagesLengthRef.current = nextLen;
  }, [messages, sessionId, scrollToBottom]);

  const refreshConversations = useCallback(async (key: Uint8Array) => {
    const list = await getConversationList(key);
    setConversations(list);
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        await purgeInconsistentVault();
        const hasVault = await hasExistingVault();

        // No mnemonic vault → never restore a stale tab session / never show PIN.
        if (!hasVault) {
          clearTabSession();
          if (!cancelled) {
            setPhase('locked');
            setCanShowRecovery(false);
            setVaultKey(null);
            setKeyPair(null);
            setSessionId('');
          }
          return;
        }

        const restored = await loadTabSession();
        if (!cancelled && restored) {
          setVaultKey(restored.vaultKey);
          setSessionId(restored.sessionId);
          setKeyPair(restored.keyPair);
          setPhase('chat');
          setCanShowRecovery(true);
          try {
            await purgeExpiredMessages();
            await refreshConversations(restored.vaultKey);
          } catch {
            // chat UI still usable; sync will retry
          }
          return;
        }

        if (!cancelled) {
          setCanShowRecovery(true);
        }
      } catch {
        clearTabSession();
        if (!cancelled) {
          setPhase('locked');
          setCanShowRecovery(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshConversations]);

  async function handleAuthUnlocked(result: {
    sessionId: string;
    keyPair: IdentityKeyPair;
    vaultKey: Uint8Array;
  }): Promise<void> {
    setVaultKey(result.vaultKey);
    setSessionId(result.sessionId);
    setKeyPair(result.keyPair);
    setPhase('chat');
    setCanShowRecovery(await vaultHasMnemonic());
    try {
      await saveTabSession({
        sessionId: result.sessionId,
        vaultKey: result.vaultKey,
        keyPair: result.keyPair,
      });
    } catch {
      // sessionStorage unavailable
    }
    await purgeExpiredMessages();
    await refreshConversations(result.vaultKey);
  }

  function totalUnread(counts: Record<string, number>): number {
    let sum = 0;
    for (const value of Object.values(counts)) {
      sum += value;
    }
    return sum;
  }

  function syncBackgroundNotifications(counts: Record<string, number>): void {
    if (typeof document === 'undefined' || !document.hidden) {
      return;
    }
    const total = totalUnread(counts);
    if (total > 0) {
      setFaviconBadge(true);
      setDocumentUnreadTitle(total);
    } else {
      clearFaviconNotifications();
    }
  }

  function bumpUnread(peerId: string): void {
    setUnreadCounts((prev) => {
      const next = {
        ...prev,
        [peerId]: (prev[peerId] ?? 0) + 1,
      };
      syncBackgroundNotifications(next);
      return next;
    });
  }

  function clearUnread(peerId: string): void {
    setUnreadCounts((prev) => {
      if (!prev[peerId]) {
        return prev;
      }
      const next = { ...prev };
      delete next[peerId];
      syncBackgroundNotifications(next);
      return next;
    });
  }

  function selectConversation(peerId: string): void {
    setActivePeer(peerId);
    clearUnread(peerId);
    setShowMembersPanel(false);
  }

  const refreshMessages = useCallback(
    async (peer: string | null, key: Uint8Array) => {
      if (!peer) {
        setMessages([]);
        return;
      }
      const history = await getMessages(peer, key);
      setMessages(history);
    },
    [],
  );

  const refreshAll = useCallback(
    async (key: Uint8Array, peer: string | null) => {
      await refreshConversations(key);
      await refreshMessages(peer, key);
    },
    [refreshConversations, refreshMessages],
  );

  const loadActiveGroup = useCallback(
    async (peer: string | null, key: Uint8Array) => {
      if (!peer?.startsWith('group:')) {
        setActiveGroup(null);
        return;
      }
      const groupId = peer.slice('group:'.length);
      const meta = await getGroupMeta(groupId, key);
      setActiveGroup(meta);
    },
    [],
  );

  useEffect(() => {
    if (phase !== 'chat' || !vaultKey) {
      return;
    }
    void (async () => {
      await purgeExpiredMessages();
      await refreshAll(vaultKey, activePeer);
      await loadActiveGroup(activePeer, vaultKey);
    })();
  }, [phase, vaultKey, activePeer, refreshAll, loadActiveGroup]);

  async function applyGroupControl(
    control: GroupControlMessage,
    myId: string,
    vk: Uint8Array,
  ): Promise<string | null> {
    const localMeta = await getGroupMeta(control.groupId, vk);

    if (!shouldAcceptGroupControl(localMeta, control)) {
      return null;
    }

    const meta = control.updatedMeta;
    const amMember = meta.members.includes(myId);

    if (control.type === 'MEMBER_REMOVED' && !amMember) {
      await deleteGroup(control.groupId);
      if (activePeerRef.current === conversationKeyForGroup(control.groupId)) {
        setActivePeer(null);
        setActiveGroup(null);
      }
      return null;
    }

    if (!amMember) {
      return null;
    }

    // NAME_CHANGED / ADMINS_UPDATED may arrive without a new key — keep local key.
    const merged: GroupMeta = {
      ...meta,
      groupKeyHex: meta.groupKeyHex || localMeta?.groupKeyHex || '',
    };
    if (!merged.groupKeyHex) {
      return null;
    }

    const syncTitle =
      control.type === 'NAME_CHANGED' ||
      (localMeta !== null && localMeta.name !== merged.name);

    await saveGroupMeta(merged, vk, { syncTitle });
    if (activePeerRef.current === conversationKeyForGroup(merged.groupId)) {
      setActiveGroup(merged);
    }
    return conversationKeyForGroup(merged.groupId);
  }

  const syncInbox = useCallback(async () => {
    const kp = keyPairRef.current;
    const vk = vaultKeyRef.current;
    const myId = sessionIdRef.current;
    if (!kp || !vk || !myId || syncingRef.current) {
      return;
    }

    syncingRef.current = true;
    try {
      await purgeExpiredMessages();

      const envelopes = await pollInbox(myId, kp.privateKey);
      const active = activePeerRef.current;

      if (envelopes.length > 0) {
        sessionNetLog.info(
          `App sync: ${envelopes.length} envelope(s) para decifrar/persistir`,
        );
      }

      for (const envelope of envelopes) {
        try {
          const outer = await openMessageEnvelope(envelope, kp);

          if (outer.control) {
            const groupPeer = await applyGroupControl(outer.control, myId, vk);
            logEnvelopeDecryptResult({
              success: true,
              persisted: Boolean(groupPeer),
              senderTruncated: truncateId(outer.senderSessionId),
            });
            if (groupPeer && groupPeer !== active) {
              bumpUnread(groupPeer);
            }
            continue;
          }

          if (outer.deleteNotice) {
            const result = await handleRemoteDeleteNotice(
              outer.deleteNotice,
              vk,
            );
            logEnvelopeDecryptResult({
              success: true,
              persisted: result.deleted,
              senderTruncated: truncateId(outer.senderSessionId),
            });
            if (result.deleted) {
              setMessages((prev) =>
                prev.filter((m) => m.id !== outer.deleteNotice!.targetMessageId),
              );
              setMediaModal((current) => {
                if (
                  current &&
                  current.messageId === outer.deleteNotice!.targetMessageId
                ) {
                  if (current.blobUrl) {
                    URL.revokeObjectURL(current.blobUrl);
                  }
                  return null;
                }
                return current;
              });
              setMenuMessageId((id) =>
                id === outer.deleteNotice!.targetMessageId ? null : id,
              );
            }
            continue;
          }

          if (outer.groupCiphertext && outer.groupNonce && outer.groupId) {
            const meta = await getGroupMeta(outer.groupId, vk);
            if (!meta) {
              logEnvelopeDecryptResult({
                success: true,
                persisted: false,
                senderTruncated: truncateId(outer.senderSessionId),
              });
              continue;
            }
            const groupKey = await resolveGroupKey(meta.groupKeyHex);
            try {
              const inner = await openGroupMessage(
                outer.groupCiphertext,
                outer.groupNonce,
                groupKey,
              );
              inner.groupId = outer.groupId;

              if (inner.deleteNotice) {
                const result = await handleRemoteDeleteNotice(
                  inner.deleteNotice,
                  vk,
                );
                logEnvelopeDecryptResult({
                  success: true,
                  persisted: result.deleted,
                  senderTruncated: truncateId(outer.senderSessionId),
                });
                if (result.deleted) {
                  setMessages((prev) =>
                    prev.filter(
                      (m) => m.id !== inner.deleteNotice!.targetMessageId,
                    ),
                  );
                  setMediaModal((current) => {
                    if (
                      current &&
                      current.messageId ===
                        inner.deleteNotice!.targetMessageId
                    ) {
                      if (current.blobUrl) {
                        URL.revokeObjectURL(current.blobUrl);
                      }
                      return null;
                    }
                    return current;
                  });
                }
                continue;
              }

              const peer = conversationKeyForGroup(outer.groupId);
              await saveIncomingOrOutgoingMessage(inner, peer, vk);
              logEnvelopeDecryptResult({
                success: true,
                persisted: true,
                senderTruncated: truncateId(outer.senderSessionId),
              });
              if (peer !== active) {
                bumpUnread(peer);
              }
            } finally {
              const s = await ensureSodium();
              s.memzero(groupKey);
            }
            continue;
          }

          const peer = outer.senderSessionId;
          await saveIncomingOrOutgoingMessage(outer, peer, vk);
          logEnvelopeDecryptResult({
            success: true,
            persisted: true,
            senderTruncated: truncateId(peer),
          });
          if (peer !== active) {
            bumpUnread(peer);
          }
        } catch {
          logEnvelopeDecryptResult({ success: false, persisted: false });
        }
      }

      // Never change the active conversation here — only refresh current view.
      await refreshAll(vk, activePeerRef.current);
      await loadActiveGroup(activePeerRef.current, vk);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.syncFail'));
    } finally {
      syncingRef.current = false;
    }
  }, [refreshAll, loadActiveGroup, t]);

  // Poll SNode swarm every ~5s while the tab is visible; pause when hidden.
  useEffect(() => {
    if (phase !== 'chat') {
      return;
    }

    const POLL_MS = 5_000;
    let timer: number | null = null;

    const stop = (): void => {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };

    const tick = (): void => {
      if (document.visibilityState === 'visible') {
        void syncInbox();
      }
    };

    const start = (): void => {
      stop();
      timer = window.setInterval(tick, POLL_MS);
    };

    const onVisibility = (): void => {
      if (document.visibilityState === 'visible') {
        clearFaviconNotifications();
        tick();
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === 'visible') {
      tick();
      start();
    }

    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [phase, syncInbox]);

  async function handleCopySessionId() {
    try {
      await navigator.clipboard.writeText(sessionId);
      setCopied(true);
      scheduleClipboardClear(30_000);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError(t('errors.copySessionFail'));
    }
  }

  function handleStartConversation(event: FormEvent) {
    event.preventDefault();
    openConversationWith(newPeerInput.trim());
  }

  function openConversationWith(rawPeer: string): void {
    const peer = sanitizeSessionId(rawPeer) ?? extractSessionId(rawPeer);
    if (!peer || !isValidSessionId(peer)) {
      setError(t('errors.invalidSessionId'));
      return;
    }
    selectConversation(peer);
    setNewPeerInput('');
    setShowNewPeer(false);
    setShowNewGroup(false);
    setShowQrScanner(false);
    setError(null);
  }

  async function handleCreateGroup(event: FormEvent) {
    event.preventDefault();
    if (!keyPair || !vaultKey) {
      return;
    }
    const name = groupNameInput.trim();
    const members = parseSessionIds(groupMembersInput).filter(
      (id) => id !== sessionId,
    );
    if (!name) {
      setError(t('errors.groupNameRequired'));
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const meta = await createGroup(name, sessionId, members);
      await saveGroupMeta(meta, vaultKey, { syncTitle: true });

      const control = buildGroupControl('INVITE', meta, sessionId);
      await broadcastGroupControl(meta, control, keyPair);

      const peer = conversationKeyForGroup(meta.groupId);
      setActivePeer(peer);
      clearUnread(peer);
      setActiveGroup(meta);
      setShowNewGroup(false);
      setGroupNameInput('');
      setGroupMembersInput('');
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.createGroupFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleInviteMember(event: FormEvent) {
    event.preventDefault();
    if (!keyPair || !vaultKey || !activeGroup) {
      return;
    }
    if (!canManageGroup(activeGroup, sessionId)) {
      setError(t('errors.adminInviteOnly'));
      return;
    }
    const memberId = sanitizeSessionId(inviteMemberInput);
    if (!memberId) {
      setError(t('errors.invalidInviteId'));
      return;
    }
    if (activeGroup.members.includes(memberId)) {
      setError(t('errors.memberExists'));
      return;
    }

    setBusy(true);
    try {
      const updated: GroupMeta = {
        ...activeGroup,
        members: [...activeGroup.members, memberId],
      };
      await saveGroupMeta(updated, vaultKey);
      setActiveGroup(updated);

      await dispatchGroupControl(
        memberId,
        buildGroupControl('INVITE', updated, sessionId),
        keyPair,
      );

      await broadcastGroupControl(
        updated,
        buildGroupControl('MEMBER_ADDED', updated, sessionId),
        keyPair,
        { excludeSessionIds: [memberId] },
      );

      setInviteMemberInput('');
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.inviteFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleRemoveMember(memberId: string) {
    if (!keyPair || !vaultKey || !activeGroup) {
      return;
    }
    if (!canManageGroup(activeGroup, sessionId)) {
      setError(t('errors.adminRemoveOnly'));
      return;
    }
    if (memberId === sessionId) {
      setError(t('errors.adminSelfRemove'));
      return;
    }

    setBusy(true);
    try {
      const rotated = await rotateGroupKey(activeGroup, memberId);
      await saveGroupMeta(rotated, vaultKey);
      setActiveGroup(rotated);

      await dispatchGroupControl(
        memberId,
        buildGroupControl(
          'MEMBER_REMOVED',
          { ...rotated, groupKeyHex: '' },
          sessionId,
        ),
        keyPair,
      );

      await broadcastGroupControl(
        rotated,
        buildGroupControl('KEY_ROTATION', rotated, sessionId),
        keyPair,
      );

      await refreshConversations(vaultKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.removeMemberFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleRenameGroup(event: FormEvent) {
    event.preventDefault();
    if (!keyPair || !vaultKey || !activeGroup) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const updated = renameGroup(activeGroup, renameInput, sessionId);
      await saveGroupMeta(updated, vaultKey, { syncTitle: true });
      setActiveGroup(updated);
      await broadcastGroupControl(
        updated,
        buildGroupControl('NAME_CHANGED', updated, sessionId),
        keyPair,
      );
      setEditingName(false);
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.renameFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handlePromote(memberId: string) {
    if (!keyPair || !vaultKey || !activeGroup) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const updated = promoteToAdmin(activeGroup, memberId, sessionId);
      await saveGroupMeta(updated, vaultKey);
      setActiveGroup(updated);
      await broadcastGroupControl(
        updated,
        buildGroupControl('ADMINS_UPDATED', updated, sessionId),
        keyPair,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.promoteFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleDemote(memberId: string) {
    if (!keyPair || !vaultKey || !activeGroup) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const updated = demoteAdmin(activeGroup, memberId, sessionId);
      await saveGroupMeta(updated, vaultKey);
      setActiveGroup(updated);
      await broadcastGroupControl(
        updated,
        buildGroupControl('ADMINS_UPDATED', updated, sessionId),
        keyPair,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.demoteFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteConversation(peer: string) {
    if (!vaultKey) {
      return;
    }
    // Optimistic UI: drop from sidebar and clear pane immediately.
    setConversations((prev) => prev.filter((c) => c.peerSessionId !== peer));
    clearUnread(peer);
    if (activePeer === peer) {
      setActivePeer(null);
      setActiveGroup(null);
      setMessages([]);
    }
    try {
      if (peer.startsWith('group:')) {
        await deleteGroup(peer.slice('group:'.length));
      } else {
        await deleteConversation(peer);
      }
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : t('errors.deleteConversationFail'),
      );
      await refreshConversations(vaultKey);
    }
  }

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    if (!keyPair || !vaultKey || !activePeer) {
      return;
    }
    const text = draft.trim();
    if (!text && !pendingFile) {
      setError(t('chat.writeOrAttach'));
      return;
    }

    setBusy(true);
    setError(null);

    const conversationKey = activeGroup
      ? conversationKeyForGroup(activeGroup.groupId)
      : activePeer;

    let inner: InnerMessage | null = null;

    try {
      let attachment: MessageAttachment | undefined;
      if (pendingFile) {
        attachment = await fileToAttachment(
          pendingFile,
          t('chat.fileTooLarge'),
        );
      }

      inner = {
        id: newMessageId(),
        senderSessionId: sessionId,
        text: text || (attachment ? t('chat.attachment') : ''),
        sentAt: Date.now(),
        viewPolicy,
      };
      if (ttlDays > 0) {
        inner.ttlDays = ttlDays;
      }
      if (attachment) {
        inner.attachment = attachment;
      }
      if (activeGroup) {
        inner.groupId = activeGroup.groupId;
      }

      // Optimistic local row — pending until SNode store confirms.
      await saveIncomingOrOutgoingMessage(inner, conversationKey, vaultKey, {
        deliveryStatus: 'pending',
      });
      setDraft('');
      setPendingFile(null);
      setViewPolicy('PERMANENT');
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      await refreshAll(vaultKey, conversationKey);

      if (activeGroup) {
        await dispatchGroupMessage(activeGroup, inner, keyPair);
        // Group fan-out uses per-member store receipts inside dispatchEnvelope.
        await updateMessageDeliveryStatus(inner.id, 'sent');
        setMessages((prev) =>
          prev.map((m) =>
            m.id === inner!.id ? { ...m, deliveryStatus: 'sent' } : m,
          ),
        );
      } else {
        const envelope = await sealMessageEnvelope(inner, activePeer);
        const receipt = await dispatchEnvelope(activePeer, envelope, undefined, {
          sessionId,
          secretKey: keyPair.privateKey,
        });
        if (!receipt.hash) {
          throw new Error(t('chat.noHash'));
        }
        sessionNetLog.success(
          `UI: mensagem confirmada com hash SNode ${receipt.hash.slice(0, 16)}…`,
        );
        await updateMessageDeliveryStatus(inner.id, 'sent');
        setMessages((prev) =>
          prev.map((m) =>
            m.id === inner!.id ? { ...m, deliveryStatus: 'sent' } : m,
          ),
        );
      }
      await refreshConversations(vaultKey);
    } catch (err) {
      if (inner) {
        try {
          await updateMessageDeliveryStatus(inner.id, 'failed');
          setMessages((prev) =>
            prev.map((m) =>
              m.id === inner!.id ? { ...m, deliveryStatus: 'failed' } : m,
            ),
          );
        } catch {
          // ignore secondary persistence errors
        }
      }
      sessionNetLog.error('Falha no envio via swarm Session', {
        error: err instanceof Error ? err.message : 'send-fail',
      });
      setError(err instanceof Error ? err.message : t('chat.sendFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleFilePicked(
    event: ChangeEvent<HTMLInputElement>,
  ): Promise<void> {
    const file = event.target.files?.[0] ?? null;
    if (!file) {
      setPendingFile(null);
      return;
    }
    try {
      await fileToAttachment(file, t('chat.fileTooLarge'));
      setPendingFile(file);
      setError(null);
    } catch (err) {
      setPendingFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      setError(err instanceof Error ? err.message : t('chat.invalidFile'));
    }
  }

  async function applyConsumedUpdate(
    updated: DecryptedMessage | null,
  ): Promise<void> {
    if (!updated || !vaultKey || !activePeer) {
      return;
    }
    if (updated.isBurned) {
      removeMessageFromUi(updated.id);
    } else {
      setMessages((prev) =>
        prev.map((m) => (m.id === updated.id ? updated : m)),
      );
    }
    await refreshConversations(vaultKey);
  }

  async function closeMediaModal(): Promise<void> {
    const current = mediaModal;
    setMediaModal(null);
    if (!current) {
      return;
    }
    if (current.blobUrl) {
      URL.revokeObjectURL(current.blobUrl);
    }
    if (current.ephemeral && vaultKey) {
      const updated = await consumeMessageView(current.messageId, vaultKey);
      await applyConsumedUpdate(updated);
    }
  }

  async function openImageViewer(
    messageId: string,
    attachment: MessageAttachment,
    ephemeral: boolean,
  ): Promise<void> {
    try {
      const { blobUrl, downloadName } =
        await createAttachmentBlobUrl(attachment);
      registerMessageBlobUrl(messageId, blobUrl);
      setMediaModal({
        kind: 'image',
        messageId,
        blobUrl,
        downloadName,
        ephemeral,
      });
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('chat.openImageFail'));
    }
  }

  async function handleProtectedDownload(messageId: string): Promise<void> {
    if (!vaultKey) {
      return;
    }
    const updated = await consumeMessageView(messageId, vaultKey);
    await applyConsumedUpdate(updated);
  }

  function removeMessageFromUi(messageId: string): void {
    setMessages((prev) => prev.filter((m) => m.id !== messageId));
    setMenuMessageId((id) => (id === messageId ? null : id));
    setMediaModal((current) => {
      if (current && current.messageId === messageId) {
        if (current.blobUrl) {
          URL.revokeObjectURL(current.blobUrl);
        }
        return null;
      }
      return current;
    });
  }

  async function handleDeleteForMe(messageId: string): Promise<void> {
    if (!vaultKey) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await deleteMessageForMe(messageId, vaultKey);
      removeMessageFromUi(messageId);
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('chat.deleteFail'));
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteForEveryone(messageId: string): Promise<void> {
    if (!vaultKey || !keyPair || !activePeer) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const isGroup = Boolean(activeGroup);
      await deleteMessageForAll(messageId, vaultKey);
      removeMessageFromUi(messageId);
      await dispatchDeleteForAll(
        messageId,
        activePeer,
        isGroup,
        keyPair,
        activeGroup ?? undefined,
      );
      await refreshConversations(vaultKey);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : t('chat.deleteAllFail'),
      );
    } finally {
      setBusy(false);
    }
  }

  function cycleViewPolicy(): void {
    setViewPolicy((current) => {
      if (current === 'PERMANENT') {
        return 'VIEW_ONCE';
      }
      if (current === 'VIEW_ONCE') {
        return 'VIEW_TWICE';
      }
      return 'PERMANENT';
    });
  }

  function viewPolicyBadge(policy: ViewPolicy): string {
    if (policy === 'VIEW_ONCE') {
      return '1';
    }
    if (policy === 'VIEW_TWICE') {
      return '2';
    }
    return '';
  }

  function expandSidebarIfNeeded(): void {
    if (isSidebarCollapsed) {
      setIsSidebarCollapsed(false);
      writeSidebarCollapsed(false);
    }
  }

  function closeActiveChat(): void {
    setActivePeer(null);
    setActiveGroup(null);
    setShowMembersPanel(false);
    setEditingName(false);
    setMenuMessageId(null);
    setChatMenuOpen(false);
  }

  async function wipeSensitiveMemory(): Promise<void> {
    resetNetworkSession();
    const s = await ensureSodium();
    const vk = vaultKeyRef.current;
    if (vk) {
      s.memzero(vk);
    }
    const kp = keyPairRef.current;
    if (kp) {
      s.memzero(kp.privateKey);
      s.memzero(kp.publicKey);
    }
    // Clear any lingering group key hex from React state by replacing meta.
    setActiveGroup(null);
    vaultKeyRef.current = null;
    keyPairRef.current = null;
  }

  function resetUiToLocked(): void {
    setVaultKey(null);
    setKeyPair(null);
    setSessionId('');
    setConversations([]);
    setUnreadCounts({});
    clearFaviconNotifications();
    setMessages([]);
    setActivePeer(null);
    setActiveGroup(null);
    setDraft('');
    setPendingFile(null);
    setMediaModal(null);
    setMenuMessageId(null);
    setChatMenuOpen(false);
    setShowNewPeer(false);
    setShowNewGroup(false);
    setShowMembersPanel(false);
    setShowIdentityShare(false);
    setShowQrScanner(false);
    setVaultModal(null);
    setPendingImportText(null);
    setPendingImportFile(null);
    setPanicClickCount(0);
    panicClickCountRef.current = 0;
    clearPanicResetTimer();
    setCopied(false);
    setError(null);
    setPhase('locked');
  }

  /** Lock session keys in RAM; IndexedDB ciphertext remains for PIN unlock. */
  async function performSecureLogout(): Promise<void> {
    setBusy(true);
    try {
      clearTabSession();
      if (mediaModal?.blobUrl) {
        URL.revokeObjectURL(mediaModal.blobUrl);
      }
      revokeAllMessageBlobUrls();
      await wipeSensitiveMemory();
      resetUiToLocked();
    } finally {
      setBusy(false);
    }
  }

  /** Irreversible wipe of identity, vault and all local history. */
  async function handlePanicPurge(): Promise<void> {
    setBusy(true);
    try {
      clearTabSession();
      if (mediaModal?.blobUrl) {
        URL.revokeObjectURL(mediaModal.blobUrl);
      }
      try {
        await wipeSensitiveMemory();
      } catch (err) {
        console.error('Erro ao zerar memória sensível:', err);
      }
      try {
        await Promise.race([
          triggerPanicPurge(),
          new Promise<void>((resolve) => {
            window.setTimeout(resolve, 5000);
          }),
        ]);
      } catch (err) {
        console.error('Erro durante a purga física:', err);
      }
    } finally {
      try {
        localStorage.clear();
        sessionStorage.clear();
      } catch {
        // ignore
      }

      // Reset React auth/session state before hard navigation.
      setVaultKey(null);
      setKeyPair(null);
      setSessionId('');
      setConversations([]);
      setUnreadCounts({});
      clearFaviconNotifications();
      setMessages([]);
      setActivePeer(null);
      setActiveGroup(null);
      setError(null);
      setPhase('locked');

      // Mandatório: destrói o runtime e reabre a tela de PIN.
      window.location.replace('/');
    }
  }

  const PANIC_CLICK_WINDOW_MS = 2500;

  function clearPanicResetTimer(): void {
    if (panicResetTimeoutRef.current !== null) {
      clearTimeout(panicResetTimeoutRef.current);
      panicResetTimeoutRef.current = null;
    }
  }

  function resetPanicClicks(): void {
    clearPanicResetTimer();
    panicClickCountRef.current = 0;
    setPanicClickCount(0);
  }

  function armPanicResetTimer(): void {
    clearPanicResetTimer();
    panicResetTimeoutRef.current = setTimeout(() => {
      panicClickCountRef.current = 0;
      setPanicClickCount(0);
      panicResetTimeoutRef.current = null;
    }, PANIC_CLICK_WINDOW_MS);
  }

  function handlePanicButtonClick(): void {
    if (busy) {
      return;
    }
    const next = panicClickCountRef.current + 1;
    if (next >= 3) {
      resetPanicClicks();
      void handlePanicPurge();
      return;
    }
    panicClickCountRef.current = next;
    setPanicClickCount(next);
    armPanicResetTimer();
  }

  useEffect(() => {
    return () => {
      if (panicResetTimeoutRef.current !== null) {
        clearTimeout(panicResetTimeoutRef.current);
        panicResetTimeoutRef.current = null;
      }
    };
  }, []);

  async function handleExportConversation(pin: string): Promise<void> {
    if (!activePeer || !vaultKey || !sessionId || !keyPair) {
      return;
    }
    setBusy(true);
    setVaultError(null);
    try {
      const history = await getMessages(activePeer, vaultKey);
      const isGroup = Boolean(activeGroup);
      const participants = isGroup
        ? [...(activeGroup?.members ?? [])]
        : [sessionId, activePeer].filter(
            (id) => id && !id.startsWith('group:'),
          );

      if (!participants.includes(sessionId)) {
        throw new Error(t('backup.accessDenied'));
      }

      const envelope = await sealConversationVault({
        pin,
        conversationId: activePeer,
        conversationType: isGroup ? 'GROUP' : 'DIRECT',
        participants,
        messages: history,
        localSessionId: sessionId,
        authorKeyPair: keyPair,
      });
      downloadVaultFile(envelope);
      setVaultModal(null);
      setChatMenuOpen(false);
    } catch (err) {
      setVaultError(
        err instanceof Error ? err.message : t('backup.exportFail'),
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleImportFilePicked(
    event: ChangeEvent<HTMLInputElement>,
  ): Promise<void> {
    const selectedFile = event.target.files?.[0] ?? null;
    // Reset input value so the same file can be re-selected later, but keep
    // the File reference in React state for the import modal lifecycle.
    event.target.value = '';

    if (!selectedFile) {
      setVaultError(t('backup.selectFile'));
      return;
    }

    try {
      const text = await selectedFile.text();

      // Validate envelope structure before asking for PIN.
      parseVaultFileEnvelope(text);

      setPendingImportFile(selectedFile);
      setPendingImportText(text);
      setVaultError(null);
      setVaultModal('import');
    } catch (err) {
      console.error('[VAULT-IMPORT] Falha ao ler/validar arquivo');
      setPendingImportFile(null);
      setPendingImportText(null);
      setVaultError(
        err instanceof VaultImportError
          ? vaultImportErrorMessage(err)
          : err instanceof Error
            ? err.message
            : t('backup.readFail'),
      );
      setVaultModal('import');
    }
  }

  async function handleImportConversation(pin: string): Promise<void> {
    let envelopeText = pendingImportText;
    if (!envelopeText && pendingImportFile) {
      try {
        envelopeText = await pendingImportFile.text();
        setPendingImportText(envelopeText);
      } catch {
        console.error('[VAULT-IMPORT] Releitura do File falhou');
      }
    }

    if (!envelopeText) {
      setVaultError(t('backup.selectFile'));
      return;
    }
    if (!vaultKey || !sessionId) {
      setVaultError(t('backup.sessionLocked'));
      return;
    }

    setBusy(true);
    setVaultError(null);
    try {
      const payload = await openConversationVault(
        envelopeText,
        pin,
        sessionId,
      );

      const isGroup = payload.conversationType === 'GROUP';
      const conversationWith = isGroup
        ? conversationKeyForGroup(
            payload.conversationId.startsWith('group:')
              ? payload.conversationId.slice('group:'.length)
              : payload.conversationId,
          )
        : payload.conversationId;

      const groupId = isGroup
        ? conversationWith.startsWith('group:')
          ? conversationWith.slice('group:'.length)
          : payload.conversationId
        : undefined;

      const asDecrypted: DecryptedMessage[] = payload.messages.map((m) => {
        const item: DecryptedMessage = {
          id: m.id,
          conversationWith,
          senderSessionId: m.senderSessionId,
          plainText: m.plainText,
          timestamp: m.timestamp,
          viewPolicy: m.viewPolicy,
          viewCount: m.viewCount,
          isBurned: m.isBurned,
        };
        if (typeof m.expiresAt === 'number') {
          item.expiresAt = m.expiresAt;
        }
        if (m.attachment) {
          item.attachment = m.attachment;
        }
        return item;
      });

      await mergeImportedMessages(
        asDecrypted,
        conversationWith,
        vaultKey,
        isGroup && groupId ? { isGroup: true, groupId } : undefined,
      );

      setVaultModal(null);
      setPendingImportText(null);
      setPendingImportFile(null);
      setActivePeer(conversationWith);
      clearUnread(conversationWith);
      await refreshAll(vaultKey, conversationWith);
      await loadActiveGroup(conversationWith, vaultKey);
    } catch (err) {
      console.error('[VAULT-IMPORT] Falha na importação');
      setVaultError(vaultImportErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const isAdmin =
    activeGroup !== null && canManageGroup(activeGroup, sessionId);
  const canSend = Boolean(draft.trim() || pendingFile);

  if (phase === 'locked') {
    return <AuthLockPanel onUnlocked={handleAuthUnlocked} />;
  }

  return (
    <div
      className={`app shell-chat${activePeer ? ' chat-open' : ''}${
        isSidebarCollapsed ? ' sidebar-collapsed' : ''
      }`}
    >
      <div className="atmosphere" aria-hidden="true" />

      <aside
        className={`sidebar${isSidebarCollapsed ? ' is-collapsed' : ''}`}
        aria-label={t('sidebar.conversations')}
      >
        <div className="sidebar-head">
          {!isSidebarCollapsed && (
            <p className="brand brand-sm">{t('auth.brand')}</p>
          )}
          <div className="sidebar-actions">
            <button
              type="button"
              className="icon-btn sidebar-toggle"
              title={
                isSidebarCollapsed
                  ? t('sidebar.expand')
                  : t('sidebar.collapse')
              }
              aria-label={
                isSidebarCollapsed
                  ? t('sidebar.expand')
                  : t('sidebar.collapse')
              }
              aria-expanded={!isSidebarCollapsed}
              onClick={() => {
                setIsSidebarCollapsed((prev) => {
                  const next = !prev;
                  writeSidebarCollapsed(next);
                  return next;
                });
              }}
            >
              {isSidebarCollapsed ? (
                <IconPanelLeftOpen size="nav" />
              ) : (
                <IconPanelLeftClose size="nav" />
              )}
            </button>
            <button
              type="button"
              className="icon-btn sidebar-action-secondary"
              title={t('sidebar.sync')}
              aria-label={t('sidebar.sync')}
              onClick={() => void syncInbox()}
              disabled={busy}
            >
              <IconRefresh size="nav" />
            </button>
            <button
              type="button"
              className={`icon-btn sidebar-action-essential${showNewPeer ? ' active' : ''}`}
              title={t('sidebar.newChat')}
              aria-label={t('sidebar.newChat')}
              onClick={() => {
                expandSidebarIfNeeded();
                setShowNewPeer((v) => !v);
                setShowNewGroup(false);
              }}
            >
              <IconMessagePlus size="nav" />
            </button>
            <button
              type="button"
              className={`icon-btn sidebar-action-essential${showQrScanner ? ' active' : ''}`}
              title={t('sidebar.scanQr')}
              aria-label={t('sidebar.scanQr')}
              onClick={() => {
                setShowQrScanner(true);
                setShowNewGroup(false);
              }}
            >
              <IconCamera size="nav" />
            </button>
            <button
              type="button"
              className="icon-btn sidebar-action-secondary"
              title={t('sidebar.importEncrypted')}
              aria-label={t('sidebar.importEncrypted')}
              onClick={() => vaultFileInputRef.current?.click()}
            >
              <IconLockImport size="nav" />
            </button>
            <input
              ref={vaultFileInputRef}
              type="file"
              accept=".vault,application/octet-stream,application/json"
              hidden
              onChange={(e) => void handleImportFilePicked(e)}
            />
            <button
              type="button"
              className={`icon-btn sidebar-action-secondary${showNewGroup ? ' active' : ''}`}
              title={t('sidebar.newGroup')}
              aria-label={t('sidebar.newGroup')}
              onClick={() => {
                expandSidebarIfNeeded();
                setShowNewGroup((v) => !v);
                setShowNewPeer(false);
              }}
            >
              <IconUsersPlus size="nav" />
            </button>
          </div>
        </div>

        <section
          className="identity-card"
          aria-label={t('sidebar.sessionId')}
          title={sessionId}
        >
          {!isSidebarCollapsed && (
            <code className="session-id">{shortenSessionId(sessionId)}</code>
          )}
          <button
            type="button"
            className="icon-btn"
            title={t('sidebar.shareIdentity')}
            aria-label={t('sidebar.shareIdentity')}
            onClick={() => setShowIdentityShare(true)}
          >
            <IconQrCode size="nav" />
          </button>
          {!isSidebarCollapsed && (
            <button
              type="button"
              className="icon-btn"
              title={t('sidebar.copySessionId')}
              aria-label={t('sidebar.copySessionId')}
              onClick={() => void handleCopySessionId()}
            >
              {copied ? <IconCheck /> : <IconCopy />}
            </button>
          )}
        </section>

        {!isSidebarCollapsed && showNewPeer && (
          <form className="new-peer-form" onSubmit={handleStartConversation}>
            <label htmlFor="new-peer">{t('sidebar.recipient')}</label>
            <div className="peer-input-row">
              <input
                id="new-peer"
                value={newPeerInput}
                onChange={(e) => setNewPeerInput(e.target.value.trim())}
                placeholder="05…"
                spellCheck={false}
              />
              <button
                type="button"
                className="icon-btn"
                title={t('sidebar.scanQr')}
                aria-label={t('sidebar.scanQr')}
                onClick={() => setShowQrScanner(true)}
              >
                <IconCamera size="nav" />
              </button>
            </div>
            <button type="submit">{t('sidebar.open')}</button>
          </form>
        )}

        {!isSidebarCollapsed && showNewGroup && (
          <form
            className="new-peer-form"
            onSubmit={(e) => void handleCreateGroup(e)}
          >
            <label htmlFor="group-name">{t('sidebar.name')}</label>
            <input
              id="group-name"
              value={groupNameInput}
              onChange={(e) => setGroupNameInput(e.target.value)}
              placeholder={t('sidebar.groupPlaceholder')}
              disabled={busy}
            />
            <label htmlFor="group-members">{t('sidebar.members')}</label>
            <textarea
              id="group-members"
              value={groupMembersInput}
              onChange={(e) => setGroupMembersInput(e.target.value)}
              placeholder="05…"
              rows={3}
              disabled={busy}
            />
            <button type="submit" disabled={busy}>
              {t('sidebar.create')}
            </button>
          </form>
        )}

        <ul className="conversation-list">
          {[...conversations]
            .sort((a, b) => {
              const ua = unreadCounts[a.peerSessionId] ?? 0;
              const ub = unreadCounts[b.peerSessionId] ?? 0;
              const aUnread = ua > 0 ? 1 : 0;
              const bUnread = ub > 0 ? 1 : 0;
              if (aUnread !== bUnread) {
                return bUnread - aUnread;
              }
              return b.updatedAt - a.updatedAt;
            })
            .map((c) => {
            const label = conversationDisplayName(
              c,
              t('sidebar.defaultGroup'),
            );
            const unread = unreadCounts[c.peerSessionId] ?? 0;
            const hasUnread = unread > 0;
            return (
              <li key={c.peerSessionId}>
                <button
                  type="button"
                  className={[
                    'conversation-item',
                    c.peerSessionId === activePeer ? 'active' : '',
                    hasUnread ? 'unread' : '',
                  ]
                    .filter(Boolean)
                    .join(' ')}
                  title={label}
                  aria-label={
                    hasUnread
                      ? t(
                          unread === 1
                            ? 'sidebar.unreadOne'
                            : 'sidebar.unreadMany',
                          { label, count: unread },
                        )
                      : label
                  }
                  onClick={() => {
                    selectConversation(c.peerSessionId);
                  }}
                >
                  <span className="peer-avatar" aria-hidden="true">
                    {conversationInitials(c)}
                    {hasUnread && (
                      <span className="peer-unread-dot" />
                    )}
                  </span>
                  <span className="conversation-meta">
                    <span className="conversation-meta-top">
                      <span
                        className={c.isGroup ? 'peer-id' : 'peer-id mono'}
                      >
                        {label}
                      </span>
                      {hasUnread && !isSidebarCollapsed && (
                        <span className="unread-badge">
                          {unread > 99 ? '99+' : unread}
                        </span>
                      )}
                    </span>
                    <span className="preview">{c.lastMessage}</span>
                    <span className="when">{formatTimestamp(c.updatedAt)}</span>
                  </span>
                </button>
                {!isSidebarCollapsed && (
                  <button
                    type="button"
                    className="trash"
                    title={t('sidebar.deleteConversation')}
                    aria-label={t('sidebar.deleteConversation')}
                    onClick={() => void handleDeleteConversation(c.peerSessionId)}
                  >
                    <IconTrash />
                  </button>
                )}
              </li>
            );
          })}
        </ul>

        <div className="sidebar-security">
          <LanguageSelector />
          {canShowRecovery && (
            <button
              type="button"
              className={
                isSidebarCollapsed ? 'icon-btn' : 'ghost sidebar-recovery-btn'
              }
              title={t('auth.showRecoveryPhrase')}
              aria-label={t('auth.showRecoveryPhrase')}
              disabled={busy}
              onClick={() => setShowRecoveryPhrase(true)}
            >
              {isSidebarCollapsed ? (
                <IconEye size="nav" />
              ) : (
                t('auth.showRecoveryPhrase')
              )}
            </button>
          )}
          <button
            type="button"
            className="icon-btn"
            title={t('sidebar.logout')}
            aria-label={t('sidebar.logout')}
            disabled={busy}
            onClick={() => void performSecureLogout()}
          >
            <IconLogOut size="nav" />
          </button>
          <button
            type="button"
            className={[
              'icon-btn',
              'panic-btn',
              panicClickCount === 1 ? 'panic-armed-1' : '',
              panicClickCount === 2 ? 'panic-armed-2' : '',
            ]
              .filter(Boolean)
              .join(' ')}
            title={
              panicClickCount === 0
                ? t('sidebar.panic')
                : panicClickCount === 1
                  ? t('sidebar.panic2')
                  : t('sidebar.panic1')
            }
            aria-label={
              panicClickCount === 0
                ? t('sidebar.panic')
                : panicClickCount === 1
                  ? t('sidebar.panic2')
                  : t('sidebar.panic1')
            }
            disabled={busy}
            onClick={handlePanicButtonClick}
          >
            <IconPanic size="nav" />
            {panicClickCount > 0 && (
              <span className="panic-remaining" aria-hidden="true">
                {3 - panicClickCount}
              </span>
            )}
          </button>
        </div>
      </aside>

      <main className="chat-pane">
        {!activePeer ? (
          <div className="chat-empty" aria-hidden="true" />
        ) : (
          <>
            <header className="chat-header">
              <div className="chat-header-main">
                <button
                  type="button"
                  className="icon-btn back-btn"
                  title={t('chat.back')}
                  aria-label={t('chat.backToChats')}
                  onClick={closeActiveChat}
                >
                  <IconChevronLeft />
                </button>
                <div className="chat-header-titles">
                  {activeGroup ? (
                    editingName && isAdmin ? (
                      <form
                        className="rename-form"
                        onSubmit={(e) => void handleRenameGroup(e)}
                      >
                        <input
                          value={renameInput}
                          onChange={(e) => setRenameInput(e.target.value)}
                          disabled={busy}
                          autoFocus
                        />
                        <button type="submit" className="compact" disabled={busy}>
                          {t('chat.ok')}
                        </button>
                        <button
                          type="button"
                          className="icon-btn"
                          onClick={() => setEditingName(false)}
                          aria-label={t('chat.cancel')}
                        >
                          <IconX />
                        </button>
                      </form>
                    ) : (
                      <>
                        <h1>
                          {activeGroup.name}
                          {isAdmin && (
                            <button
                              type="button"
                              className="icon-btn edit-name"
                              title={t('chat.rename')}
                              aria-label={t('chat.renameGroup')}
                              onClick={() => {
                                setRenameInput(activeGroup.name);
                                setEditingName(true);
                              }}
                            >
                              <IconPencil size="sm" />
                            </button>
                          )}
                        </h1>
                        <p className="subtitle">
                          {activeGroup.members.length} · v
                          {activeGroup.keyVersion}
                        </p>
                      </>
                    )
                  ) : (
                    <>
                      <h1>{shortenSessionId(activePeer)}</h1>
                      <p className="subtitle peer-full">{activePeer}</p>
                    </>
                  )}
                </div>
              </div>
              <div className="header-actions">
                {activeGroup && isAdmin && (
                  <button
                    type="button"
                    className={`icon-btn${showMembersPanel ? ' active' : ''}`}
                    title={t('chat.members')}
                    aria-label={t('chat.membersAria')}
                    onClick={() => setShowMembersPanel((v) => !v)}
                  >
                    <IconShield size="nav" />
                  </button>
                )}
                <label className="ttl-field icon-btn" title={t('chat.ttl')}>
                  <IconClock size="nav" />
                  <select
                    value={ttlDays}
                    aria-label={t('chat.ttl')}
                    onChange={(e) =>
                      setTtlDays(Number(e.target.value) as TtlOption)
                    }
                  >
                    <option value={0}>{t('chat.ttlNone')}</option>
                    <option value={1}>{t('chat.ttl1d')}</option>
                    <option value={7}>{t('chat.ttl7d')}</option>
                    <option value={30}>{t('chat.ttl30d')}</option>
                  </select>
                </label>
                <div
                  className={`chat-header-menu${chatMenuOpen ? ' open' : ''}`}
                >
                  <button
                    type="button"
                    className={`icon-btn${chatMenuOpen ? ' active' : ''}`}
                    title={t('chat.options')}
                    aria-label={t('chat.options')}
                    aria-expanded={chatMenuOpen}
                    onClick={() => setChatMenuOpen((v) => !v)}
                  >
                    <IconMoreHorizontal size="nav" />
                  </button>
                  {chatMenuOpen && (
                    <div className="msg-menu-panel chat-options-panel" role="menu">
                      <button
                        type="button"
                        role="menuitem"
                        disabled={busy}
                        onClick={() => {
                          setVaultError(null);
                          setVaultModal('export');
                          setChatMenuOpen(false);
                        }}
                      >
                        <IconLockExport size="sm" />
                        {t('chat.exportEncrypted')}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </header>

            {activeGroup && isAdmin && showMembersPanel && (
              <section className="members-panel">
                <h2>{t('chat.members')}</h2>
                <ul>
                  {activeGroup.members.map((member) => {
                    const memberIsAdmin = activeGroup.admins.includes(member);
                    return (
                      <li key={member}>
                        <div className="member-id">
                          <code>{shortenSessionId(member)}</code>
                          {memberIsAdmin && (
                            <span className="badge">{t('chat.admin')}</span>
                          )}
                        </div>
                        <div className="member-actions">
                          {!memberIsAdmin && (
                            <button
                              type="button"
                              className="ghost compact"
                              onClick={() => void handlePromote(member)}
                              disabled={busy}
                            >
                              {t('chat.admin')}
                            </button>
                          )}
                          {memberIsAdmin && (
                            <button
                              type="button"
                              className="ghost compact"
                              onClick={() => void handleDemote(member)}
                              disabled={busy || activeGroup.admins.length <= 1}
                            >
                              {t('chat.removeAdmin')}
                            </button>
                          )}
                          {member !== sessionId && (
                            <button
                              type="button"
                              className="ghost compact danger"
                              onClick={() => void handleRemoveMember(member)}
                              disabled={busy}
                            >
                              {t('chat.remove')}
                            </button>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ul>
                <form onSubmit={(e) => void handleInviteMember(e)}>
                  <label htmlFor="invite-member">{t('chat.invite')}</label>
                  <div className="invite-row">
                    <input
                      id="invite-member"
                      value={inviteMemberInput}
                      onChange={(e) =>
                        setInviteMemberInput(e.target.value.trim())
                      }
                      placeholder="05…"
                      spellCheck={false}
                      disabled={busy}
                    />
                    <button type="submit" className="compact" disabled={busy}>
                      +
                    </button>
                  </div>
                </form>
              </section>
            )}

            <section
              ref={scrollContainerRef}
              className="history"
              aria-live="polite"
              onScroll={handleHistoryScroll}
            >
              {messages.length > 0 && (
                <ul>
                  {messages.map((msg) => {
                    const mine = msg.senderSessionId === sessionId;
                    const protectedMsg =
                      !msg.isBurned && msg.viewPolicy !== 'PERMANENT';
                    const left = remainingViews(msg);

                    if (msg.isBurned) {
                      return (
                        <li key={msg.id} className="bubble burned">
                          <span className="meta burned-icon" aria-label={t('chat.expired')}>
                            <IconFlame size="sm" />
                          </span>
                        </li>
                      );
                    }

                    return (
                      <li
                        key={msg.id}
                        className={[
                          mine ? 'bubble mine' : 'bubble theirs',
                          mine && msg.deliveryStatus === 'pending'
                            ? 'pending'
                            : '',
                          mine && msg.deliveryStatus === 'failed'
                            ? 'failed'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                      >
                        <div className="bubble-header">
                          <span className="meta">
                            {mine
                              ? t('chat.you')
                              : shortenSessionId(msg.senderSessionId)}{' '}
                            · {formatTimestamp(msg.timestamp)}
                            {msg.expiresAt
                              ? ` · ${formatTimestamp(msg.expiresAt)}`
                              : ''}
                            {mine && msg.deliveryStatus === 'pending'
                              ? ` · ${t('chat.statusSending')}`
                              : ''}
                            {mine && msg.deliveryStatus === 'failed'
                              ? ` · ${t('chat.statusFailed')}`
                              : ''}
                            {mine && msg.deliveryStatus === 'sent'
                              ? ` · ${t('chat.statusSent')}`
                              : ''}
                          </span>
                          <div
                            className={`msg-menu${menuMessageId === msg.id ? ' open' : ''}`}
                          >
                            <button
                              type="button"
                              className="msg-menu-toggle"
                              aria-label={t('chat.messageActions')}
                              aria-expanded={menuMessageId === msg.id}
                              disabled={busy}
                              onClick={() =>
                                setMenuMessageId((id) =>
                                  id === msg.id ? null : msg.id,
                                )
                              }
                            >
                              <IconTrash />
                            </button>
                            {menuMessageId === msg.id && (
                              <div className="msg-menu-panel" role="menu">
                                <button
                                  type="button"
                                  role="menuitem"
                                  disabled={busy}
                                  onClick={() =>
                                    void handleDeleteForMe(msg.id)
                                  }
                                >
                                  {t('chat.deleteForMe')}
                                </button>
                                {(mine ||
                                  (Boolean(activeGroup) && isAdmin)) && (
                                  <button
                                    type="button"
                                    role="menuitem"
                                    disabled={busy}
                                    onClick={() =>
                                      void handleDeleteForEveryone(msg.id)
                                    }
                                  >
                                    {t('chat.deleteForEveryone')}
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </div>

                        {protectedMsg && (
                          <span className="view-badge">
                            {msg.viewPolicy === 'VIEW_ONCE'
                              ? '1×'
                              : `${Number.isFinite(left) ? left : '—'}×`}
                          </span>
                        )}

                        {protectedMsg &&
                        !msg.attachment &&
                        msg.plainText ? (
                          <button
                            type="button"
                            className="reveal-btn"
                            onClick={() =>
                              setMediaModal({
                                kind: 'text',
                                messageId: msg.id,
                                text: msg.plainText,
                                ephemeral: true,
                              })
                            }
                          >
                            <IconEye size="sm" />
                          </button>
                        ) : null}

                        {!protectedMsg && msg.plainText ? (
                          <SafeMessageText text={msg.plainText} />
                        ) : null}

                        {protectedMsg &&
                        msg.attachment &&
                        !msg.attachment.mimeType.startsWith('image/') &&
                        msg.plainText &&
                        !isDefaultAttachmentCaption(
                          msg.plainText,
                          t('chat.attachment'),
                        ) ? (
                          <button
                            type="button"
                            className="reveal-btn"
                            onClick={() =>
                              setMediaModal({
                                kind: 'text',
                                messageId: msg.id,
                                text: msg.plainText,
                                ephemeral: true,
                              })
                            }
                          >
                            <IconEye size="sm" />
                          </button>
                        ) : null}

                        {msg.attachment ? (
                          <SafeAttachment
                            attachment={msg.attachment}
                            protectedMedia={protectedMsg}
                            onOpenImage={(attachment) =>
                              void openImageViewer(
                                msg.id,
                                attachment,
                                protectedMsg,
                              )
                            }
                            onDownload={
                              protectedMsg
                                ? () => handleProtectedDownload(msg.id)
                                : undefined
                            }
                          />
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              )}
              <div
                ref={bottomAnchorRef}
                className="history-bottom-anchor"
                aria-hidden="true"
              />
              {!isAtBottom && (
                <button
                  type="button"
                  className="scroll-to-bottom-btn"
                  title={t('chat.scrollToLatest')}
                  aria-label={t('chat.scrollToLatest')}
                  onClick={() => {
                    scrollToBottom('smooth');
                    setUnreadCount(0);
                    setIsAtBottom(true);
                  }}
                >
                  <IconChevronDown size="nav" />
                  {unreadCount > 0 && (
                    <span className="scroll-to-bottom-badge">
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                  )}
                </button>
              )}
            </section>

            <div className="composer-wrap">
              {pendingFile && (
                <p className="pending-file">
                  <span className="pending-file-kind">
                    {isImageMime(pendingFile.type) ||
                    /\.(png|jpe?g|webp)$/i.test(pendingFile.name) ? (
                      <>
                        <IconImage size="sm" />
                        <span>{t('chat.imageAlt')}</span>
                      </>
                    ) : (
                      <>
                        <IconFile size="sm" />
                        <span>{t('chat.document')}</span>
                      </>
                    )}
                  </span>
                  <span className="spacer" />
                  <button
                    type="button"
                    className="icon-btn"
                    aria-label={t('chat.removeAttachment')}
                    onClick={() => {
                      setPendingFile(null);
                      if (fileInputRef.current) {
                        fileInputRef.current.value = '';
                      }
                    }}
                  >
                    <IconX size="sm" />
                  </button>
                </p>
              )}
              <form className="composer" onSubmit={(e) => void handleSend(e)}>
                <div className="composer-pill">
                  <label className="attach-btn" title={t('chat.attach')}>
                    <IconPaperclip />
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp,application/pdf,.txt,.csv,.docx,.xlsx"
                      onChange={(e) => void handleFilePicked(e)}
                      disabled={busy}
                      aria-label={t('chat.attachFile')}
                    />
                  </label>
                  <input
                    type="text"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder={t('chat.placeholder')}
                    disabled={busy}
                    aria-label={t('chat.messageAria')}
                  />
                  <button
                    type="button"
                    className={`view-cycle${viewPolicy !== 'PERMANENT' ? ' active' : ''}`}
                    title={
                      viewPolicy === 'PERMANENT'
                        ? t('chat.viewPermanent')
                        : viewPolicy === 'VIEW_ONCE'
                          ? t('chat.viewOnce')
                          : t('chat.viewTwice')
                    }
                    aria-label={t('chat.viewMode')}
                    onClick={cycleViewPolicy}
                    disabled={busy}
                  >
                    <IconFlame />
                    <span className="view-badge-num" aria-hidden="true">
                      {viewPolicy === 'PERMANENT' ? (
                        <IconInfinity size="sm" />
                      ) : (
                        viewPolicyBadge(viewPolicy)
                      )}
                    </span>
                  </button>
                </div>
                <button
                  type="submit"
                  className={`send-btn${canSend ? ' ready' : ''}`}
                  disabled={busy || !canSend}
                  aria-label={t('chat.send')}
                  title={t('chat.send')}
                >
                  <IconSend className="send-icon" />
                </button>
              </form>
            </div>
          </>
        )}

        {mediaModal && (
          <div
            className="media-modal-backdrop"
            role="presentation"
            onClick={() => void closeMediaModal()}
          >
            <div
              className="media-modal"
              role="dialog"
              aria-modal="true"
              onClick={(e) => e.stopPropagation()}
              onContextMenu={(e) => e.preventDefault()}
            >
              <button
                type="button"
                className="modal-close"
                aria-label={t('chat.close')}
                onClick={() => void closeMediaModal()}
              >
                <IconX size="sm" />
              </button>
              {mediaModal.kind === 'image' && mediaModal.blobUrl ? (
                <>
                  <img
                    src={mediaModal.blobUrl}
                    alt={t('chat.imageAlt')}
                    onContextMenu={(e) => e.preventDefault()}
                    onLoad={() => {
                      if (mediaModal.ephemeral && mediaModal.blobUrl) {
                        URL.revokeObjectURL(mediaModal.blobUrl);
                      }
                    }}
                  />
                  {!mediaModal.ephemeral && (
                    <a
                      href={mediaModal.blobUrl}
                      download={mediaModal.downloadName ?? 'imagem.jpg'}
                      className="download-link"
                      aria-label={t('chat.download')}
                      title={t('chat.download')}
                    >
                      <IconDownload size="md" />
                    </a>
                  )}
                </>
              ) : (
                <pre className="secret-text">
                  {sanitizePlainMessageText(mediaModal.text ?? '')}
                </pre>
              )}
            </div>
          </div>
        )}

      </main>

      {showIdentityShare && (
        <IdentityShareModal
          sessionId={sessionId}
          onClose={() => setShowIdentityShare(false)}
        />
      )}
      {showQrScanner && (
        <QrScannerModal
          onClose={() => setShowQrScanner(false)}
          onDetected={(peer) => openConversationWith(peer)}
        />
      )}
      {vaultModal && (
        <PinVaultModal
          mode={vaultModal}
          busy={busy}
          error={vaultError}
          onCancel={() => {
            setVaultModal(null);
            setVaultError(null);
            // Keep pendingImportFile/Text so the user can reopen after a typo
            // only when they explicitly cancel — clear on cancel as before.
            setPendingImportText(null);
            setPendingImportFile(null);
          }}
          onConfirm={(pin) => {
            return vaultModal === 'export'
              ? handleExportConversation(pin)
              : handleImportConversation(pin);
          }}
        />
      )}
      {showRecoveryPhrase && (
        <ShowRecoveryPhraseModal
          onClose={() => setShowRecoveryPhrase(false)}
        />
      )}
    </div>
  );
}

