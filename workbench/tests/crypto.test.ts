import { describe, expect, it, beforeAll } from 'vitest';

beforeAll(() => {
  process.env.SAWB_DATA_KEY = 'a'.repeat(64);
});

describe('server crypto', () => {
  it('round-trips AES-GCM and rejects tampering or wrong purpose', async () => {
    const { encrypt, decrypt } = await import('../server/crypto');
    const blob = encrypt(Buffer.from('secret evidence'), 'evidence:1');
    expect(decrypt(blob, 'evidence:1').toString()).toBe('secret evidence');
    expect(() => decrypt(blob, 'evidence:2')).toThrow();
    const tampered = Buffer.from(blob);
    tampered[tampered.length - 1] ^= 1;
    expect(() => decrypt(tampered, 'evidence:1')).toThrow();
  });

  it('hashes and verifies passwords and enforces policy', async () => {
    const { hashPassword, verifyPassword, passwordProblem } = await import('../server/crypto');
    const h = hashPassword('Correct-Horse-9');
    expect(verifyPassword('Correct-Horse-9', h)).toBe(true);
    expect(verifyPassword('wrong', h)).toBe(false);
    expect(passwordProblem('short')).not.toBeNull();
    expect(passwordProblem('longbutnodigitsX')).not.toBeNull();
    expect(passwordProblem('Long-enough-123')).toBeNull();
  });
});
