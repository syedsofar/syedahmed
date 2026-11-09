import express from 'express';
import cookieParser from 'cookie-parser';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config';
import { loadKey } from './crypto';
import { flush, loadDb } from './store';
import { seed } from './seed';
import { api } from './routes';

loadKey();
loadDb();
seed();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (config.secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; object-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  );
  next();
});

app.use(cookieParser());
app.use('/api', (req, res, next) => (req.path.endsWith('/export') ? next() : express.json({ limit: '2mb' })(req, res, next)));
app.use('/api', (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use('/api', api);

if (fs.existsSync(config.clientDist)) {
  app.use(express.static(config.clientDist, { index: false }));
  app.get('*', (_req, res) => res.sendFile(path.join(config.clientDist, 'index.html')));
}

const server = app.listen(config.port, config.host, () => {
  console.log(`Security Architecture Workbench API on http://${config.host}:${config.port} (${config.mode} environment)`);
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => { flush(); server.close(() => process.exit(0)); });
}
