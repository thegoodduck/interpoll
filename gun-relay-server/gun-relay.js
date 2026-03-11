#!/usr/bin/env node
// gun-relay.js
// Community GunDB relay server for InterPoll.
// Provides a standard Gun.js relay with radisk persistence and a /health endpoint.
//
// Usage:
//   node gun-relay.js
//   PORT=9000 node gun-relay.js

import express from 'express';
import Gun from 'gun';
import cors from 'cors';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = parseInt(process.env.PORT || '8765', 10);
const DATA_DIR = process.env.GUN_DATA_DIR || path.join(__dirname, 'gun-data');

const app = express();

// CORS — allow any origin so browser clients can connect
app.use(cors({ origin: true, credentials: true }));

// ─── Rate limiting middleware ────────────────────────────────────────────────
// Simple sliding-window counter keyed by IP address.

const rateLimitStore = new Map(); // ip -> { count, resetAt }

const RATE_WINDOW = 60_000; // 1 minute
const RATE_MAX = 120;       // 120 requests per minute per IP (generous for Gun sync)

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket.remoteAddress
    || 'unknown';
}

app.use((req, res, next) => {
  const ip = getClientIp(req);
  const now = Date.now();
  let entry = rateLimitStore.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_WINDOW };
    rateLimitStore.set(ip, entry);
  }
  entry.count++;
  if (entry.count > RATE_MAX) {
    res.set('Retry-After', '60');
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
});

// Purge stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, 300_000);

// Health check endpoint (spec section 8.5)
const startedAt = Date.now();

app.get('/health', (_req, res) => {
  const gun = app.get('gun');
  let peerCount = 0;
  try {
    const peers = gun?._.opt?.peers || {};
    peerCount = Object.values(peers).filter((p) => p?.wire?.readyState === 1).length;
  } catch {
    // ignore
  }

  res.json({
    status: 'ok',
    uptime: Math.floor((Date.now() - startedAt) / 1000),
    peers: peerCount,
    timestamp: Date.now(),
  });
});

// ─── REST query API (spec section 18.3–18.4) ────────────────────────────────

// GET /db/search?prefix=<prefix>&limit=<limit>
// Scans Gun's in-memory graph for souls matching the given prefix.
app.get('/db/search', (req, res) => {
  const prefix = req.query.prefix;
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);

  if (!prefix) {
    return res.status(400).json({ error: 'prefix query parameter required' });
  }

  const gunInstance = app.get('gun');
  const results = [];

  try {
    gunInstance.get(prefix).map().once((data, key) => {
      if (!data || !key || String(key).startsWith('_')) return;
      if (results.length < limit) {
        results.push({ soul: `${prefix}/${key}`, data });
      }
    });
  } catch {
    // ignore Gun errors
  }

  // Gun .once() is async; return after a short delay
  setTimeout(() => {
    res.json({ results });
  }, 200);
});

// GET /db/soul?soul=<path>
// Fetch a single Gun node by its full path.
app.get('/db/soul', (req, res) => {
  const soul = req.query.soul;

  if (!soul) {
    return res.status(400).json({ error: 'soul query parameter required' });
  }

  const gunInstance = app.get('gun');
  const parts = soul.split('/');
  let node = gunInstance;
  for (const part of parts) {
    node = node.get(part);
  }

  node.once((data) => {
    if (!data) {
      return res.status(404).json({ error: 'not found' });
    }
    res.json({ soul, data });
  });

  // Timeout fallback
  setTimeout(() => {
    if (!res.headersSent) {
      res.status(404).json({ error: 'not found' });
    }
  }, 2000);
});

// Create HTTP server and attach Gun
const server = http.createServer(app);

const gun = Gun({
  web: server,
  radisk: true,
  file: DATA_DIR,
  localStorage: false,
  axe: false,
  multicast: false,
});

// Stash reference for the health endpoint
app.set('gun', gun);

server.listen(PORT, () => {
  console.log(`Gun relay server listening on http://localhost:${PORT}/gun`);
  console.log(`Health check at http://localhost:${PORT}/health`);
  console.log(`Data directory: ${DATA_DIR}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down Gun relay...');
  server.close(() => {
    console.log('Gun relay stopped.');
    process.exit(0);
  });
});
