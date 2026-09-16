/**
 * Zod schemas for conversation vault envelope + decrypted backup payload.
 */

import { z } from 'zod';
import { SESSION_ID_REGEX } from './validators';

const hexString = z
  .string()
  .min(2)
  .regex(/^[0-9a-fA-F]+$/, 'Campo hex inválido');

const sessionIdSchema = z
  .string()
  .regex(SESSION_ID_REGEX, 'sessionId deve ser 05 + 64 hex');

/**
 * Outer encrypted vault file (validated BEFORE PIN / decrypt).
 */
export const vaultFileEnvelopeSchema = z
  .object({
    format: z.literal('SESSION_CONVERSATION_VAULT'),
    version: z.number().int().positive(),
    salt: hexString,
    nonce: hexString,
    ciphertext: hexString,
    authorSessionId: sessionIdSchema,
    signature: hexString,
  })
  .strict();

export type VaultFileEnvelopeParsed = z.infer<typeof vaultFileEnvelopeSchema>;

const MAX_VAULT_MESSAGES = 5_000;
const MAX_TEXT_CHARS = 8_000;

/**
 * Canonical logical backup shape (user-facing schema).
 * Used to reject malformed logical backups when present.
 */
export const vaultBackupSchema = z
  .object({
    version: z.number().int().positive(),
    type: z.enum(['direct', 'group', 'community']),
    sessionId: sessionIdSchema,
    messages: z
      .array(
        z
          .object({
            id: z.string().min(1).max(128),
            text: z.string().max(MAX_TEXT_CHARS),
            timestamp: z.number().positive(),
            sender: z.string().min(1).max(128),
          })
          .strict(),
      )
      .max(MAX_VAULT_MESSAGES),
  })
  .strict();

export type VaultBackupCanonical = z.infer<typeof vaultBackupSchema>;

/**
 * Decrypted Ictus vault payload (SESSION_VAULT_BACKUP_V1).
 */
export const vaultDecryptedPayloadSchema = z
  .object({
    magic: z.literal('SESSION_VAULT_BACKUP_V1'),
    conversationId: z.string().min(1).max(200),
    conversationType: z.enum(['DIRECT', 'GROUP']),
    exportedAt: z.number().positive(),
    participants: z.array(z.string()).max(500),
    messages: z
      .array(
        z
          .object({
            id: z.string().min(1).max(128),
            conversationWith: z.string().min(1).max(200),
            senderSessionId: z.string().min(1).max(128),
            plainText: z.string().max(MAX_TEXT_CHARS),
            timestamp: z.number().positive(),
            expiresAt: z.number().positive().optional(),
            attachment: z.unknown().optional(),
            viewPolicy: z.string().optional(),
            viewCount: z.number().int().nonnegative().optional(),
            isBurned: z.boolean().optional(),
          })
          .passthrough(),
      )
      .max(MAX_VAULT_MESSAGES),
  })
  .passthrough();

export type VaultDecryptedPayloadParsed = z.infer<
  typeof vaultDecryptedPayloadSchema
>;

export const VAULT_SCHEMA_ERROR =
  'Arquivo de backup corrompido ou fora do formato padrão';
