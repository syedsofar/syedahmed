import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config';

let key: Buffer | null = null;

/** Load the data-encryption key. In production it must be supplied; in demonstration mode a
 *  local key file is generated (0600) so the demo works out of the box. */
export function loadKey(): Buffer {
  if (key) return key;
  if (config.dataKeyHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(config.dataKeyHex)) throw new Error('SAWB_DATA_KEY must be 64 hex characters (32 bytes).');
    key = Buffer.from(config.dataKeyHex, 'hex');
    return key;
  }
  if (config.mode === 'production') throw new Error('SAWB_DATA_KEY is required in production mode.');
  fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(config.dataDir, '.demo-data-key');
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    console.warn('[security] Generated a local demonstration data key at', file, '- set SAWB_DATA_KEY for any non-demo use.');
  }
  key = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  return key;
}

const MAGIC = Buffer.from('SAWB1');

/** AES-256-GCM. Layout: MAGIC | iv(12) | tag(16) | ciphertext. AAD binds the blob to its purpose. */
export function encrypt(plain: Buffer, aad = ''): Buffer {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', loadKey(), iv);
  if (aad) c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), ct]);
}

export function decrypt(blob: Buffer, aad = ''): Buffer {
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Encrypted blob has an unknown format.');
  const iv = blob.subarray(5, 17);
  const tag = blob.subarray(17, 33);
  const d = crypto.createDecipheriv('aes-256-gcm', loadKey(), iv);
  if (aad) d.setAAD(Buffer.from(aad));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(blob.subarray(33)), d.final()]);
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, saltHex, hashHex] = stored.split('$');
  if (alg !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(expected, actual);
}

export const sha256 = (data: Buffer | string) => crypto.createHash('sha256').update(data).digest('hex');
export const newId = () => crypto.randomUUID();
export const token = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

/** Password policy for accounts created or changed through the UI. */
export function passwordProblem(pw: string): string | null {
  if (pw.length < 12) return 'Password must be at least 12 characters.';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/\d/.test(pw)) return 'Password must contain upper-case, lower-case and a digit.';
  return null;
}
