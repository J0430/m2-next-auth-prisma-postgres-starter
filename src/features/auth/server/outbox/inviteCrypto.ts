// Invite delivery token encryption and fragment-link construction.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const AES_GCM_ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_HEX_PATTERN = /^[a-f0-9]{64}$/i;

function parseInviteDeliveryKey(keyHex: string): Buffer {
  if (!KEY_HEX_PATTERN.test(keyHex)) {
    throw new Error("INVITE_DELIVERY_KEY_INVALID");
  }
  return Buffer.from(keyHex, "hex");
}

export function encryptInviteDeliveryToken(rawToken: string, keyHex: string): Uint8Array {
  const key = parseInviteDeliveryKey(keyHex);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(AES_GCM_ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(rawToken, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]);
}

export function decryptInviteDeliveryToken(ciphertext: Uint8Array, keyHex: string): string {
  try {
    const key = parseInviteDeliveryKey(keyHex);
    const bytes = Buffer.from(ciphertext);
    if (bytes.length <= IV_BYTES + TAG_BYTES) throw new Error("INVITE_DELIVERY_DECRYPT_FAILED");

    const iv = bytes.subarray(0, IV_BYTES);
    const tag = bytes.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const encryptedToken = bytes.subarray(IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv(AES_GCM_ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encryptedToken), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("INVITE_DELIVERY_DECRYPT_FAILED");
  }
}

export function createInviteTokenDecryptor(keyring: ReadonlyMap<number, string>) {
  return (ciphertext: Uint8Array, keyVersion: number | null): string => {
    if (keyVersion === null) throw new Error("INVITE_DELIVERY_DECRYPT_FAILED");
    const keyHex = keyring.get(keyVersion);
    if (!keyHex) throw new Error("INVITE_DELIVERY_DECRYPT_FAILED");
    return decryptInviteDeliveryToken(ciphertext, keyHex);
  };
}

type OutboxKeyVersionReader = {
  outboxEmail: { findMany(input: { where: { keyVersion: { not: null } }; distinct: ["keyVersion"]; select: { keyVersion: true } }): Promise<Array<{ keyVersion: number | null }>> };
};

export async function validateStoredInviteKeyVersions(
  reader: OutboxKeyVersionReader,
  keyring: ReadonlyMap<number, string>,
): Promise<void> {
  const rows = await reader.outboxEmail.findMany({
    where: { keyVersion: { not: null } }, distinct: ["keyVersion"], select: { keyVersion: true },
  });
  for (const row of rows) {
    if (row.keyVersion === null || !keyring.has(row.keyVersion)) throw new Error("INVITE_DELIVERY_KEY_VERSION_MISSING");
  }
}

export function buildInviteAcceptUrl(rawToken: string, baseUrl: string): string {
  const url = new URL("/invite", baseUrl);
  url.hash = `token=${encodeURIComponent(rawToken)}`;
  return url.toString();
}
