#!/usr/bin/env node
// community-relay-server.js
// Community WebSocket relay server for InterPoll.
// Implements the full TurkeyLuck protocol (spec sections 4, 8) so that
// any InterPoll client can connect out-of-the-box.
//
// Usage:
//   node community-relay-server.js
//   PORT=8080 FRONTEND_ORIGIN=http://localhost:5173 node community-relay-server.js

import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import crypto from 'crypto';
import { URL, fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Configuration ──────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '8080', 10);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

// ─── Rate limiting ──────────────────────────────────────────────────────────
// Simple sliding-window counters keyed by IP address.

const rateLimitState = {
  http: new Map(),   // ip -> { count, resetAt }
  ws: new Map(),     // ip -> { count, resetAt }
  wsMsg: new Map(),  // peerId -> { count, resetAt }
};

const RATE_LIMITS = {
  httpWindow: 60_000,       // 1 minute
  httpMax: 60,              // 60 HTTP requests per minute per IP
  wsConnWindow: 60_000,     // 1 minute
  wsConnMax: 10,            // 10 new WS connections per minute per IP
  wsMsgWindow: 10_000,      // 10 seconds
  wsMsgMax: 100,            // 100 messages per 10s per connection
};

function checkRateLimit(store, key, windowMs, max) {
  const now = Date.now();
  let entry = store.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
    store.set(key, entry);
  }
  entry.count++;
  return entry.count <= max;
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket.remoteAddress
    || 'unknown';
}

// Purge stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const store of Object.values(rateLimitState)) {
    for (const [key, entry] of store) {
      if (now > entry.resetAt) store.delete(key);
    }
  }
}, 300_000);

// ─── State ──────────────────────────────────────────────────────────────────

const clients = new Map();   // peerId -> WebSocket
const rooms = new Map();     // roomId -> Set<peerId>

// Vote-authorization registry (spec section 8.1)
// key = `${pollId}:${deviceId}`
const voteRegistry = new Set();

// Append-only receipt log (spec section 8.2)
const RECEIPT_LOG_FILE = path.join(__dirname, 'storage.txt');

// ─── Message cache (spec section 4.6) ───────────────────────────────────────

const MESSAGE_CACHE_FILE = path.join(__dirname, 'message-cache.json');
const MAX_CACHED_MESSAGES = 500;
let messageCache = [];

try {
  if (fs.existsSync(MESSAGE_CACHE_FILE)) {
    messageCache = JSON.parse(fs.readFileSync(MESSAGE_CACHE_FILE, 'utf8'));
    console.log(`Loaded ${messageCache.length} cached messages from disk`);
  }
} catch {
  messageCache = [];
}

function cacheMessage(msg) {
  if (!msg || !msg.type) return;
  const cacheable = ['new-poll', 'new-block', 'sync-response', 'new-event'];
  const type = msg.type || msg.data?.type;
  if (!cacheable.includes(type)) return;
  messageCache.push({ ...msg, _cachedAt: Date.now() });
  while (messageCache.length > MAX_CACHED_MESSAGES) messageCache.shift();
}

function saveMessageCache() {
  try {
    fs.writeFileSync(MESSAGE_CACHE_FILE, JSON.stringify(messageCache));
  } catch (err) {
    console.error('Failed to save message cache:', err.message);
  }
}

// Persist cache every 30 seconds
setInterval(saveMessageCache, 30_000);

// ─── HTTP server & API endpoints ────────────────────────────────────────────

const server = http.createServer();

server.on('request', (req, res) => {
  // CORS headers for any browser origin
  const origin = req.headers.origin || FRONTEND_ORIGIN;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Rate limit HTTP requests
  const clientIp = getClientIp(req);
  if (!checkRateLimit(rateLimitState.http, clientIp, RATE_LIMITS.httpWindow, RATE_LIMITS.httpMax)) {
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
    res.end(JSON.stringify({ error: 'Too many requests' }));
    return;
  }

  if (!req.url) {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── POST /api/vote-authorize (spec section 8.1) ──

  if (req.method === 'POST' && url.pathname === '/api/vote-authorize') {
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const pollId = String(data.pollId || '');
        const deviceId = String(data.deviceId || '');

        if (!pollId || !deviceId) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ allowed: false, reason: 'missing pollId or deviceId' }));
          return;
        }

        const key = `${pollId}:${deviceId}`;
        const alreadyVoted = voteRegistry.has(key);
        if (!alreadyVoted) {
          voteRegistry.add(key);
        }

        // Audit log
        const logEntry = {
          type: 'vote-authorize',
          pollId,
          deviceId,
          allowed: !alreadyVoted,
          timestamp: Date.now(),
        };
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify(logEntry) + '\n', () => {});

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          allowed: !alreadyVoted,
          reason: alreadyVoted ? 'already voted' : undefined,
        }));
      } catch (error) {
        console.error('Error in /api/vote-authorize:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ allowed: true }));
      }
    });
    return;
  }

  // ── POST /api/receipts (spec section 8.2) ──

  if (req.method === 'POST' && url.pathname === '/api/receipts') {
    let body = '';
    req.on('data', (chunk) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const logEntry = {
          type: 'receipt',
          payload: data,
          timestamp: Date.now(),
        };
        fs.appendFile(RECEIPT_LOG_FILE, JSON.stringify(logEntry) + '\n', (err) => {
          if (err) console.error('Failed to write receipt log:', err);
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (error) {
        console.error('Error in /api/receipts:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  // ── GET /api/me — returns null user for community server (no OAuth) ──

  if (req.method === 'GET' && url.pathname === '/api/me') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: null }));
    return;
  }

  // ── GET /health — server health check ──

  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      uptime: Math.floor((Date.now() - startedAt) / 1000),
      peers: clients.size,
      cachedMessages: messageCache.length,
      timestamp: Date.now(),
    }));
    return;
  }

  // ── Fallback 404 ──

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

// ─── WebSocket relay (spec section 4) ───────────────────────────────────────

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  let peerId = null;

  // Rate limit WebSocket connections per IP
  const clientIp = getClientIp(req);
  if (!checkRateLimit(rateLimitState.ws, clientIp, RATE_LIMITS.wsConnWindow, RATE_LIMITS.wsConnMax)) {
    ws.close(1008, 'Too many connections');
    return;
  }

  // Per-connection message rate limit key (use socket address until peerId is set)
  const msgKey = `${clientIp}:${Date.now()}`;

  console.log(`New connection from ${req.socket.remoteAddress}`);

  // Send welcome message (spec section 4.3)
  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'Connected to P2P relay',
    timestamp: Date.now(),
  }));

  ws.on('message', (raw) => {
    // Rate limit messages per connection
    const limitKey = peerId || msgKey;
    if (!checkRateLimit(rateLimitState.wsMsg, limitKey, RATE_LIMITS.wsMsgWindow, RATE_LIMITS.wsMsgMax)) {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: 'error', message: 'Rate limited — slow down' }));
      }
      return;
    }

    try {
      const data = JSON.parse(raw.toString());

      switch (data.type) {
        // ── ping/pong (spec section 4.2) ──
        case 'ping':
          if (ws.readyState === 1) {
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
          }
          break;

        // ── register (spec section 4.2) ──
        case 'register':
          peerId = data.peerId;
          clients.set(peerId, ws);
          console.log(`Peer registered: ${peerId} (Total: ${clients.size})`);

          // Broadcast updated peer list (spec section 4.3)
          broadcast({
            type: 'peer-list',
            peers: Array.from(clients.keys()),
          });

          // Replay cached messages to new client (spec section 4.6)
          if (messageCache.length > 0) {
            console.log(`Replaying ${messageCache.length} cached messages to ${peerId}`);
            for (const msg of messageCache) {
              try { ws.send(JSON.stringify(msg)); } catch { /* ignore */ }
            }
          }
          break;

        // ── join-room (spec section 4.2) ──
        case 'join-room': {
          const roomId = data.roomId || 'default';
          if (!rooms.has(roomId)) {
            rooms.set(roomId, new Set());
          }
          rooms.get(roomId).add(peerId);
          console.log(`${peerId} joined room: ${roomId}`);
          break;
        }

        // ── broadcast wrapper (spec section 4.2) ──
        case 'broadcast':
          console.log(`Broadcasting ${data.data?.type || 'message'} from ${peerId}`);
          broadcastToOthers(peerId, data.data);
          cacheMessage(data.data);
          break;

        // ── direct message (spec section 4.2) ──
        case 'direct': {
          const targetWs = clients.get(data.targetPeer);
          if (targetWs && targetWs.readyState === 1) {
            targetWs.send(JSON.stringify(data.data));
          }
          break;
        }

        // ── Unwrapped P2P message types (spec section 4.4) ──
        case 'new-poll':
        case 'new-block':
        case 'new-event':
        case 'request-sync':
        case 'sync-response':
          console.log(`Broadcasting ${data.type} from ${peerId}`);
          broadcastToOthers(peerId, data);
          cacheMessage(data);
          break;

        default:
          console.log('Unknown message type:', data.type);
      }
    } catch (error) {
      console.error('Error handling message:', error);
    }
  });

  ws.on('close', () => {
    if (peerId) {
      clients.delete(peerId);
      rateLimitState.wsMsg.delete(peerId);

      // Remove from all rooms
      rooms.forEach((peers, roomId) => {
        peers.delete(peerId);
        if (peers.size === 0) rooms.delete(roomId);
      });

      console.log(`Peer disconnected: ${peerId} (Total: ${clients.size})`);

      // Notify others (spec section 4.3)
      broadcast({
        type: 'peer-left',
        peerId,
      });
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error.message);
  });
});

// ─── Broadcast helpers ──────────────────────────────────────────────────────

function broadcast(message) {
  const payload = JSON.stringify(message);
  clients.forEach((ws) => {
    if (ws.readyState === 1) ws.send(payload);
  });
}

function broadcastToOthers(excludePeerId, message) {
  const payload = JSON.stringify(message);
  clients.forEach((ws, id) => {
    if (id !== excludePeerId && ws.readyState === 1) ws.send(payload);
  });
}

// ─── Boot ───────────────────────────────────────────────────────────────────

const startedAt = Date.now();

server.listen(PORT, () => {
  console.log(`InterPoll community relay server running on ws://localhost:${PORT}`);
  console.log(`HTTP API at http://localhost:${PORT}`);
  console.log(`  POST /api/vote-authorize`);
  console.log(`  POST /api/receipts`);
  console.log(`  GET  /api/me`);
  console.log(`  GET  /health`);
  console.log('Waiting for connections...');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down relay server...');
  saveMessageCache();
  wss.clients.forEach((ws) => ws.close());
  server.close(() => {
    console.log('Relay server stopped.');
    process.exit(0);
  });
});
