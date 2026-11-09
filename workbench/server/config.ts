import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export type EnvMode = 'demonstration' | 'production';

const mode = (process.env.SAWB_ENV ?? 'demonstration') as EnvMode;
if (mode !== 'demonstration' && mode !== 'production') {
  throw new Error('SAWB_ENV must be "demonstration" or "production".');
}

export const config = {
  mode,
  port: Number(process.env.PORT ?? 4310),
  host: process.env.HOST ?? '127.0.0.1',
  dataDir: process.env.SAWB_DATA_DIR ?? path.join(here, 'data'),
  clientDist: path.join(here, '..', 'client', 'dist'),
  /** 64 hex chars (32 bytes). Required in production. */
  dataKeyHex: process.env.SAWB_DATA_KEY,
  sessionIdleMinutes: Number(process.env.SAWB_SESSION_IDLE_MINUTES ?? 30),
  sessionMaxHours: Number(process.env.SAWB_SESSION_MAX_HOURS ?? 10),
  maxUploadBytes: Number(process.env.SAWB_MAX_UPLOAD_MB ?? 15) * 1024 * 1024,
  secureCookies: process.env.NODE_ENV === 'production' && process.env.SAWB_SECURE_COOKIES !== 'false',
  demoPassword: process.env.SAWB_DEMO_PASSWORD,
  ai: {
    provider: process.env.SAWB_AI_PROVIDER || null,
    endpoint: process.env.SAWB_AI_ENDPOINT || null,
    allowDocuments: process.env.SAWB_AI_ALLOW_DOCUMENTS === 'true',
  },
};
