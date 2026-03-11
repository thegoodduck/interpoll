# InterPoll Protocol Specification

> **Protocol codename:** **TurkeyLuck**  
> **Version:** 2.0  
> **Date:** 2026-03-11  
> **Authors:** @thegoodduck & @theendless11

> This specification describes the full data schema, relay protocol, cryptography, and API surface used by InterPoll. It is published so that anyone can build a compatible client or server. The production backend uses a hardened implementation; community edition releases may lag behind, but this spec is always current.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [GunDB Data Schema](#3-gundb-data-schema)
4. [WebSocket Relay Protocol](#4-websocket-relay-protocol)
5. [Blockchain (Local Audit Chain)](#5-blockchain-local-audit-chain)
6. [Nostr-Style Signed Events](#6-nostr-style-signed-events)
7. [Cryptography](#7-cryptography)
8. [HTTP API Endpoints](#8-http-api-endpoints)
9. [Server Discovery & Mesh](#9-server-discovery--mesh)
10. [Reference: Default Endpoints](#10-reference-default-endpoints)
11. [End-to-End Encryption](#11-end-to-end-encryption)
12. [Private & Encrypted Communities](#12-private--encrypted-communities)
13. [Chat & Messaging](#13-chat--messaging)
14. [WebRTC Peer Connections](#14-webrtc-peer-connections)
15. [Snapshot Sync](#15-snapshot-sync)
16. [Data Versioning](#16-data-versioning)
17. [User Identity & Pseudonyms](#17-user-identity--pseudonyms)
18. [Search & Indexing API](#18-search--indexing-api)
19. [Content Moderation](#19-content-moderation)

---

## 1. Overview

InterPoll is a decentralised polling and community platform. Data is replicated through two complementary channels:

| Channel | Purpose |
|---------|---------|
| **GunDB** | Persistent, eventually-consistent graph database for communities, polls, posts, comments, and images. |
| **WebSocket relay** | Real-time fan-out of chain blocks, sync requests, peer discovery, and server-list gossip. |

Clients also maintain a **local append-only blockchain** (IndexedDB) for tamper-evident audit logging of votes and actions, signed with Schnorr signatures over secp256k1.

---

## 2. Architecture

```
┌──────────┐  GunDB (ws)   ┌──────────────┐
│  Client   │◄─────────────►│  Gun Relay   │
│  (Browser)│               │  Server      │
│           │  WSS          ├──────────────┤
│           │◄─────────────►│  WS Relay    │
│           │               │  Server      │
└──────────┘               └──────────────┘
      │  BroadcastChannel
      ▼
┌──────────┐
│ Other Tab│
└──────────┘
```

- **Gun Relay Server** — standard Gun.js relay (`gun` npm package) with `radisk: true`.
- **WS Relay Server** — lightweight WebSocket hub that registers peers, relays broadcasts, caches recent messages, and exposes HTTP endpoints for vote authorization and OAuth.
- **BroadcastChannel** — same-origin tab-to-tab sync (mirrors the WSS message types).

---

## 3. GunDB Data Schema

GunDB is used as the primary replicated data store. All data lives under top-level graph nodes. The Gun peer URL is of the form `https://<host>/gun` (upgrades to WebSocket internally).

### 3.1 Gun Client Configuration

```js
Gun({
  peers: ['https://interpoll2.onrender.com/gun'],
  localStorage: true,   // use browser localStorage as cache
  radisk: false,         // client-side disk persistence off
  axe: false             // disable AXE protocol logging
})
```

### 3.2 Communities

**Path:** `gun.get('communities').get('<communityId>')`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique ID, format: `c-<slugified-name>` |
| `name` | `string` | Raw community name |
| `displayName` | `string` | Human-readable display name |
| `description` | `string` | Community description |
| `creatorId` | `string` | Device fingerprint of creator |
| `createdAt` | `number` | Unix timestamp in milliseconds |
| `memberCount` | `number` | Current member count |
| `postCount` | `number` | Current post count |

**Rules** are stored as a numbered map:

**Path:** `gun.get('communities').get('<communityId>').get('rules')`

```json
{ "0": "Be respectful", "1": "No spam" }
```

### 3.3 Polls

Polls are stored in **two locations** (dual-write for fast community-scoped lookups):

1. **Global:** `gun.get('polls').get('<pollId>')`
2. **Community-scoped:** `gun.get('communities').get('<communityId>').get('polls').get('<pollId>')`

**Poll ID format:** `poll-<timestampMs>-<random9chars>`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Poll ID |
| `communityId` | `string` | Parent community ID |
| `authorId` | `string` | Device fingerprint of author |
| `authorName` | `string` | Display name of author |
| `question` | `string` | Poll question text |
| `description` | `string` | Optional description |
| `createdAt` | `number` | Unix timestamp (ms) |
| `expiresAt` | `number` | Expiry timestamp (ms) |
| `allowMultipleChoices` | `boolean` | Allow selecting multiple options |
| `showResultsBeforeVoting` | `boolean` | Show results before casting a vote |
| `requireLogin` | `boolean` | Require OAuth login |
| `isPrivate` | `boolean` | Require invite code |
| `totalVotes` | `number` | Running vote total |
| `isExpired` | `boolean` | Whether poll has expired |

#### 3.3.1 Poll Options

**Path:** `…get('<pollId>').get('options')`

Stored as a numbered map (keys are string indices `"0"`, `"1"`, …):

```json
{
  "0": { "id": "poll-xxx-option-0", "text": "Option A", "votes": 0 },
  "1": { "id": "poll-xxx-option-1", "text": "Option B", "votes": 0 }
}
```

**Option ID format:** `<pollId>-option-<index>`

#### 3.3.2 Voting

To cast a vote, increment the `votes` field on the chosen option(s) and increment `totalVotes` on the poll:

```
poll.get('options').get('<index>').get('votes')  ← current + 1
poll.get('totalVotes')                           ← current + N
```

Both the global and community-scoped copies must be updated.

#### 3.3.3 Invite Codes (Private Polls)

**Path:** `…get('<pollId>').get('inviteCodes')` — legacy numbered map  
**Path:** `…get('<pollId>').get('inviteCodesByCode')` — preferred keyed-by-code map

```json
// inviteCodesByCode
{ "A1B2C3D4": { "used": false }, "E5F6G7H8": { "used": true } }
```

Codes are 8-character uppercase alphanumeric strings. To consume: set `used: true`.

### 3.4 Posts

Dual-written like polls:

1. **Global:** `gun.get('posts').get('<postId>')`
2. **Community-scoped:** `gun.get('communities').get('<communityId>').get('posts').get('<postId>')`

**Post ID format:** `post-<timestampMs>-<random9chars>`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Post ID |
| `communityId` | `string` | Parent community ID |
| `authorId` | `string` | Device fingerprint |
| `authorName` | `string` | Display name |
| `title` | `string` | Post title |
| `content` | `string` | Post body text |
| `imageIPFS` | `string` | Optional IPFS CID for full image |
| `imageThumbnail` | `string` | Optional base64 thumbnail |
| `createdAt` | `number` | Unix timestamp (ms) |
| `upvotes` | `number` | Upvote count |
| `downvotes` | `number` | Downvote count |
| `score` | `number` | `upvotes - downvotes` |
| `commentCount` | `number` | Number of comments |

### 3.5 Comments

**Path:** `gun.get('comments').get('<commentId>')`

Each field is written individually (Gun.js field-per-put pattern):

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Comment ID, format: `comment_<timestampMs>_<random9chars>` |
| `postId` | `string` | Parent post ID |
| `communityId` | `string` | Community ID |
| `authorId` | `string` | Device fingerprint |
| `authorName` | `string` | Display name |
| `content` | `string` | Comment text |
| `parentId` | `string?` | Parent comment ID (for threading) |
| `createdAt` | `number` | Unix timestamp (ms) |
| `upvotes` | `number` | |
| `downvotes` | `number` | |
| `score` | `number` | |
| `edited` | `boolean` | |
| `editedAt` | `number?` | |

**Comment index on post:**  
`gun.get('posts').get('<postId>').get('comments').set({ commentId, createdAt })`

### 3.6 Images

**Path:** `gun.get('images').get('<imageId>')`

| Field | Type | Description |
|-------|------|-------------|
| `data` | `string` | Base64-encoded image data |
| `thumbnail` | `string` | Base64-encoded thumbnail |
| `size` | `number` | Original file size in bytes |
| `uploadedAt` | `number` | Unix timestamp (ms) |

**Image ID format:** `img-<timestampMs>-<random9chars>`

---

## 4. WebSocket Relay Protocol

The WebSocket relay is a **JSON-over-WebSocket** message hub. All messages are JSON objects with a `type` field.

**Default URL:** `wss://<host>` (port 8080 in development)

### 4.1 Connection Lifecycle

```
Client                          Relay Server
  │                                  │
  │──── WebSocket connect ──────────►│
  │◄─── { type:"welcome" } ─────────│
  │──── { type:"register", peerId }─►│
  │◄─── { type:"peer-list", peers }──│  (broadcast to all)
  │──── { type:"join-room", roomId }►│
  │                                  │
  │  ... message exchange ...        │
  │                                  │
  │◄─── { type:"pong" } ────────────│  (in response to ping)
  │                                  │
  │     [connection closes]          │
  │◄─── { type:"peer-left", peerId }│  (broadcast to others)
```

### 4.2 Client → Server Messages

#### `register`
Register this client with the relay.

```json
{ "type": "register", "peerId": "<random-id>" }
```

`peerId` — random string generated via `Math.random().toString(36).substring(7)`.

#### `join-room`
Join a named room (currently only `"default"` is used).

```json
{ "type": "join-room", "roomId": "default" }
```

#### `ping`
Keep-alive heartbeat. Client sends every **25 seconds**.

```json
{ "type": "ping" }
```

#### `broadcast`
Relay a message to all other connected peers. The payload is wrapped:

```json
{
  "type": "broadcast",
  "data": {
    "type": "<message-type>",
    "data": { ... },
    "timestamp": 1708500000000
  }
}
```

The relay unwraps and sends `data` to all peers except the sender.

#### `direct`
Send to a specific peer (not commonly used):

```json
{ "type": "direct", "targetPeer": "<peerId>", "data": { ... } }
```

### 4.3 Server → Client Messages

#### `welcome`
Sent immediately on connection.

```json
{ "type": "welcome", "message": "Connected to P2P relay", "timestamp": 1708500000000 }
```

#### `peer-list`
Broadcast to all clients whenever a peer registers.

```json
{ "type": "peer-list", "peers": ["abc123", "def456", "ghi789"] }
```

#### `peer-left`
Broadcast when a peer disconnects.

```json
{ "type": "peer-left", "peerId": "abc123" }
```

#### `pong`
Response to client `ping`.

```json
{ "type": "pong", "timestamp": 1708500000000 }
```

### 4.4 Application-Level Broadcast Messages

These are sent via the `broadcast` wrapper (§4.2) or directly as top-level types. The relay forwards them to all other peers. The relay also **caches** content-bearing messages (`new-poll`, `new-block`, `sync-response`, `new-event`) and replays them to newly connecting clients.

#### `new-block`
A new chain block was created locally.

```json
{
  "type": "new-block",
  "data": {
    "index": 5,
    "timestamp": 1708500000000,
    "previousHash": "abcdef...",
    "voteHash": "123456...",
    "signature": "schnorr-sig-hex...",
    "currentHash": "789abc...",
    "nonce": 0,
    "pubkey": "x-only-pubkey-hex...",
    "actionType": "vote",
    "actionLabel": "Vote on poll-xxx"
  }
}
```

#### `request-sync`
Ask peers to send their chain blocks. Supports incremental sync via `lastIndex`.

```json
{
  "type": "request-sync",
  "data": {
    "peerId": "abc123",
    "lastIndex": 4
  }
}
```

- `lastIndex: -1` — request all blocks (full sync).
- `lastIndex: N` — only send blocks with `index > N`.

#### `sync-response`
Response containing chain blocks.

```json
{
  "type": "sync-response",
  "data": {
    "blocks": [ /* array of ChainBlock objects */ ],
    "peerId": "def456"
  }
}
```

#### `new-event`
A Nostr-style signed event (see §6).

```json
{
  "type": "new-event",
  "data": {
    "id": "sha256-hex-64chars",
    "pubkey": "x-only-pubkey-64chars",
    "created_at": 1708500,
    "kind": 101,
    "tags": [["poll_id", "poll-xxx"]],
    "content": "{\"choice\":\"Option A\",\"deviceId\":\"fp123\"}",
    "sig": "schnorr-sig-128chars"
  }
}
```

#### `new-poll`
Legacy/shortcut: a new poll was created (also synced via GunDB).

```json
{ "type": "new-poll", "data": { /* Poll object */ } }
```

#### `peer-addresses`
Peer shares its relay addresses for mesh discovery.

```json
{
  "type": "peer-addresses",
  "data": {
    "peerId": "abc123",
    "relayUrl": "wss://interpoll.onrender.com",
    "gunPeers": ["https://interpoll2.onrender.com/gun"],
    "joinedAt": 1708500000000
  }
}
```

#### `server-list`
Peer shares its known server list for federation.

```json
{
  "type": "server-list",
  "data": {
    "peerId": "abc123",
    "servers": [
      {
        "websocket": "wss://interpoll.onrender.com",
        "gun": "https://interpoll2.onrender.com/gun",
        "api": "https://interpoll.onrender.com",
        "addedBy": "abc123",
        "firstSeen": 1708500000000
      }
    ]
  }
}
```

### 4.5 Reconnection Strategy

Clients use **exponential backoff** on disconnect:

| Attempt | Delay |
|---------|-------|
| 1 | 1 s |
| 2 | 2 s |
| 3 | 4 s |
| 4 | 8 s |
| … | … |
| max | 30 s |

Formula: `min(1000 * 2^attempt, 30000)` ms. Attempts never stop (`maxReconnectAttempts = Infinity`).

### 4.6 Message Cache (Server-Side)

The relay server maintains an in-memory message cache (persisted to `message-cache.json` every 30 s). Cacheable message types: `new-poll`, `new-block`, `sync-response`, `new-event`. Maximum **500** cached messages. On peer registration, all cached messages are replayed to the new client.

---

## 5. Blockchain (Local Audit Chain)

Each client maintains a local append-only blockchain in **IndexedDB** (database name: `interpoll-db`, version `1`).

### 5.1 Block Structure (`ChainBlock`)

| Field | Type | Description |
|-------|------|-------------|
| `index` | `number` | Sequential block index (0 = genesis) |
| `timestamp` | `number` | Unix timestamp (ms) |
| `previousHash` | `string` | SHA-256 hex of previous block (genesis: `"0"×64`) |
| `voteHash` | `string` | SHA-256 of the action data (genesis: `"0"×64`) |
| `signature` | `string` | Schnorr signature (hex, 128 chars) |
| `currentHash` | `string` | SHA-256 hex of this block |
| `nonce` | `number` | Always `0` (reserved) |
| `pubkey` | `string?` | Signer's x-only public key (hex, 64 chars) |
| `actionType` | `string?` | `"vote"` \| `"community-create"` \| `"post-create"` |
| `actionLabel` | `string?` | Human-readable label |
| `eventId` | `string?` | Reference to NostrEvent that produced this block |

### 5.2 Block Hashing

The `currentHash` is computed as:

```
SHA-256(JSON.stringify({
  index,
  timestamp,
  previousHash,
  voteHash,
  signature,
  nonce,
  pubkey?,       // included only if present
  actionType?,   // included only if present
  actionLabel?   // included only if present
}))
```

JSON keys are serialized in the order listed above.

### 5.3 Block Signing

The signature covers:

```
Schnorr.sign(
  SHA-256(JSON.stringify({
    index,
    voteHash,
    previousHash
  })),
  privateKey
)
```

### 5.4 Vote Hash

```
SHA-256(JSON.stringify(voteData, sortedKeys))
```

Where keys are sorted alphabetically via `Object.keys(vote).sort()`.

### 5.5 Validation Rules

1. `block.index === previousBlock.index + 1`
2. `block.previousHash === previousBlock.currentHash`
3. `block.currentHash === computedHash(block)`
4. If `block.pubkey` is present: Schnorr signature must verify against `{index, voteHash, previousHash}`
5. Genesis block: `index === 0`, `previousHash === "0"×64`

### 5.6 Sync Protocol

1. On connect, client sends `request-sync` with `lastIndex` (highest local block index, or `-1`).
2. Peers respond with `sync-response` containing blocks where `block.index > lastIndex`.
3. Received blocks are validated against the local chain before being accepted.
4. Conflicts (same index, different hash) are ignored — first-write wins locally.

### 5.7 Vote Object

| Field | Type | Description |
|-------|------|-------------|
| `pollId` | `string` | Target poll ID |
| `choice` | `string` | Selected option text |
| `timestamp` | `number` | Unix timestamp (ms) |
| `deviceId` | `string` | Device fingerprint hash |

### 5.8 Receipt

After voting, a 12-word BIP-39 mnemonic is generated as a voter receipt:

| Field | Type | Description |
|-------|------|-------------|
| `blockIndex` | `number` | Chain block index |
| `voteHash` | `string` | Hash of the vote data |
| `chainHeadHash` | `string` | Chain head hash at time of vote |
| `mnemonic` | `string` | 12-word BIP-39 mnemonic |
| `timestamp` | `number` | Unix timestamp (ms) |
| `pollId` | `string` | Poll ID |

---

## 6. Nostr-Style Signed Events

InterPoll uses a Nostr-compatible event format (NIP-01) for cryptographic proof of authorship. Events are broadcast alongside chain blocks.

### 6.1 Event Structure

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | SHA-256 of canonical serialization (hex, 64 chars) |
| `pubkey` | `string` | x-only public key (hex, 64 chars) |
| `created_at` | `number` | Unix timestamp in **seconds** |
| `kind` | `number` | Event kind (see below) |
| `tags` | `string[][]` | Array of tag arrays |
| `content` | `string` | JSON-encoded payload |
| `sig` | `string` | Schnorr signature of `id` (hex, 128 chars) |

### 6.2 Event Kinds

| Kind | Name | Description |
|------|------|-------------|
| `100` | `POLL_CREATION` | A new poll was created |
| `101` | `VOTE_CAST` | A vote was cast |
| `102` | `POLL_UPDATE` | A poll was updated |
| `103` | `POST_CREATION` | A new post was created |

### 6.3 Canonical Serialization (NIP-01)

```
JSON.stringify([0, pubkey, created_at, kind, tags, content])
```

### 6.4 Event ID

```
id = SHA-256(canonical_serialization)   // hex
```

### 6.5 Signature

```
sig = Schnorr.sign(hexToBytes(id), hexToBytes(privateKey))  // hex
```

### 6.6 Verification

1. Recompute `id` from `{pubkey, created_at, kind, tags, content}` — must match `event.id`.
2. Verify `schnorr.verify(sig, id, pubkey)` — must return `true`.

### 6.7 Event Tag Conventions

| Tag | Used in kinds | Description |
|-----|---------------|-------------|
| `["poll_id", "<id>"]` | 100, 101, 102 | Reference poll |
| `["community", "<id>"]` | 100, 103 | Reference community |
| `["option", "<optionId>"]` | 101 | Selected option |
| `["post_id", "<id>"]` | 103 | Reference post |

### 6.8 Event Content Payloads

**Kind 100 (POLL_CREATION):**
```json
{
  "question": "What is your favorite color?",
  "description": "",
  "options": ["Red", "Blue", "Green"],
  "durationDays": 7,
  "allowMultipleChoices": false,
  "showResultsBeforeVoting": true,
  "requireLogin": false,
  "isPrivate": false
}
```

**Kind 101 (VOTE_CAST):**
```json
{ "choice": "Red", "deviceId": "sha256-fingerprint-hex" }
```

**Kind 102 (POLL_UPDATE):**
```json
{ "totalVotes": 42 }
```

**Kind 103 (POST_CREATION):**
```json
{ "title": "Hello World", "content": "My first post", "imageIPFS": "" }
```

---

## 7. Cryptography

### 7.1 Key Pair

- **Curve:** secp256k1
- **Signature scheme:** Schnorr (x-only public keys, BIP-340)
- **Private key:** 32 bytes, hex-encoded (64 chars)
- **Public key:** 32 bytes x-only, hex-encoded (64 chars)
- **Storage:** IndexedDB (`metadata` object store, key `"nostr-keypair"`)

### 7.2 Hashing

All hashing uses **SHA-256** producing hex-encoded output (64 chars).

### 7.3 Mnemonics

BIP-39 12-word English mnemonics are used as human-readable vote receipts.

### 7.4 Device Fingerprint

A SHA-256 hash of:
```
navigator.userAgent | navigator.language | timezoneOffset | colorDepth | screenResolution | hardwareConcurrency
```

---

## 8. HTTP API Endpoints

The WebSocket relay server also serves HTTP endpoints on the same port.

### 8.1 `POST /api/vote-authorize`

Server-side double-vote protection. The server maintains an in-memory `Set` of `pollId:deviceId` pairs.

**Request:**
```json
{ "pollId": "poll-xxx", "deviceId": "fingerprint-hash" }
```

**Response:**
```json
{ "allowed": true }
// or
{ "allowed": false, "reason": "already voted" }
```

### 8.2 `POST /api/receipts`

Append an audit receipt to the server's append-only log file (`storage.txt`).

**Request:** Any JSON object.

**Response:**
```json
{ "ok": true }
```

### 8.3 `GET /api/me`

Return the currently authenticated user (cookie-based session).

**Response:**
```json
{
  "user": {
    "provider": "google",
    "sub": "1234567890",
    "email": "user@example.com",
    "name": "John Doe",
    "picture": "https://..."
  }
}
```

### 8.4 OAuth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/google/start` | GET | Redirect to Google OAuth |
| `/auth/google/callback` | GET | Google OAuth callback |
| `/auth/microsoft/start` | GET | Redirect to Microsoft OAuth |
| `/auth/microsoft/callback` | GET | Microsoft OAuth callback |
| `/auth/logout` | POST | Clear session cookie |

### 8.5 Gun Relay Health Check

On the Gun relay server (separate port, default `8765`):

| Endpoint | Method | Response |
|----------|--------|----------|
| `/health` | GET | `{ "status": "ok", "uptime": <seconds>, "peers": <count>, "timestamp": <ms> }` |

---

## 9. Server Discovery & Mesh

### 9.1 Known Server Object

```typescript
interface KnownServer {
  websocket: string;   // WSS relay URL (unique key)
  gun: string;         // Gun relay URL
  api: string;         // HTTP API base URL
  addedBy: string;     // peerId that reported this server
  firstSeen: number;   // Unix timestamp (ms)
}
```

### 9.2 Discovery Flow

1. On connect, client broadcasts `peer-addresses` with its own relay URLs.
2. On connect, client broadcasts `server-list` with all known servers.
3. When a `server-list` message is received, the client merges unknown servers into its local list.
4. Known servers are persisted in `localStorage` under key `interpoll_known_servers`.

### 9.3 Relay Configuration Override

Clients store relay overrides in `localStorage` under key `interpoll_relay_config`:

```json
{
  "websocket": "wss://custom-server.example.com",
  "gun": "https://custom-gun.example.com/gun",
  "api": "https://custom-server.example.com"
}
```

Empty strings fall back to built-in defaults.

---

## 10. Reference: Default Endpoints

| Service | Default URL |
|---------|-------------|
| WebSocket relay | `wss://interpoll.onrender.com` |
| Gun relay | `https://interpoll2.onrender.com/gun` |
| HTTP API | `https://interpoll.onrender.com` |

### 10.1 Running Your Own Relay

**Gun Relay Server:**
```bash
cd gun-relay-server
npm install
node gun-relay.js
# Listens on port 8765 by default (set PORT env var to override)
```

**WebSocket Relay Server:**
```bash
cd community-relay-server
npm install
node community-relay-server.js
# Listens on port 8080 by default (set PORT env var to override)
```

Both servers are stateless enough to run anywhere. The Gun relay persists data to disk via `radisk` and exposes a REST query API. The WS relay caches messages in `message-cache.json` and vote-authorisation state in memory (lost on restart).

---

## Appendix A: IndexedDB Schema

**Database:** `interpoll-db` (version `1`)

| Object Store | Key Path | Indexes |
|-------------|----------|---------|
| `blocks` | `index` | `by-hash` → `currentHash` |
| `votes` | `timestamp` | `by-poll` → `pollId` |
| `receipts` | `mnemonic` | `by-block` → `blockIndex` |
| `polls` | `id` | — |
| `metadata` | (out-of-line) | — |

## Appendix B: BroadcastChannel

Same-origin tab sync uses `BroadcastChannel('interpoll-sync')`. Message format is identical to the WSS application-level messages (§4.4). Messages include a `peerId` field; tabs ignore messages from their own `peerId`.

## Appendix C: Complete Message Type Reference

| Message Type | Direction | Cacheable | Description |
|-------------|-----------|-----------|-------------|
| `register` | C→S | No | Register peer |
| `join-room` | C→S | No | Join a room |
| `ping` | C→S | No | Keep-alive |
| `broadcast` | C→S | — | Wrapper for relayed messages |
| `direct` | C→S | No | Direct peer message |
| `welcome` | S→C | No | Connection acknowledgment |
| `peer-list` | S→C | No | Active peer list |
| `peer-left` | S→C | No | Peer disconnected |
| `pong` | S→C | No | Ping response |
| `new-block` | P2P | **Yes** | New chain block |
| `new-poll` | P2P | **Yes** | New poll created |
| `new-event` | P2P | **Yes** | Signed Nostr event |
| `request-sync` | P2P | No | Request chain sync |
| `sync-response` | P2P | **Yes** | Chain sync payload |
| `peer-addresses` | P2P | No | Relay address sharing |
| `server-list` | P2P | No | Known server gossip |
| `chat-start` | P2P | No | Initiate chat session |
| `chat-message` | P2P | No | Encrypted chat message |
| `chat-typing` | P2P | No | Typing indicator |
| `chat-read` | P2P | No | Read receipt |
| `chat-delivered` | P2P | No | Delivery confirmation |
| `chat-read-receipt` | P2P | No | Read acknowledgment |
| `chatroom-message` | P2P | No | Group chat room message |
| `rtc-offer` | P2P | No | WebRTC SDP offer |
| `rtc-answer` | P2P | No | WebRTC SDP answer |
| `rtc-ice` | P2P | No | WebRTC ICE candidate |
| `snapshot-offer` | P2P | No | Bulk state transfer offer |
| `snapshot-accept` | P2P | No | Accept snapshot transfer |
| `snapshot-chunk` | P2P | No | Snapshot data chunk |
| `snapshot-complete` | P2P | No | Snapshot transfer complete |
| `snapshot-cancel` | P2P | No | Cancel snapshot transfer |

---

## 11. End-to-End Encryption

InterPoll supports optional end-to-end encryption for communities, chat rooms, and direct messages using AES-256-GCM via the Web Crypto API.

### 11.1 Encryption Scheme

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key derivation | PBKDF2 (SHA-256, 100 000 iterations) |
| IV | 12 bytes, randomly generated per encryption |
| Salt | 16 bytes, randomly generated per key derivation |

### 11.2 Encrypted Blob Format

All encrypted data is stored as an `EncryptedBlob`:

```typescript
interface EncryptedBlob {
  ciphertext: string;   // Base64-encoded ciphertext
  iv: string;           // Base64-encoded 12-byte IV
  salt: string;         // Base64-encoded 16-byte salt
  version: number;      // Schema version (currently 1)
}
```

### 11.3 Server-Wide Encryption

A server operator can enable encryption for all content via the client's encryption config:

```typescript
interface EncryptionConfig {
  encryptAll: boolean;          // Encrypt all content by default
  serverPassword: string;       // Password for AES key derivation
  requireInviteToJoin: boolean; // Require invite link to access
}
```

Stored in `localStorage` under key `interpoll_encryption_config`.

### 11.4 Key Storage

Encryption keys are stored in IndexedDB:

```typescript
interface StoredEncryptionKey {
  id: string;          // Key identifier (e.g., community ID)
  key: CryptoKey;      // Web Crypto API key object
  salt: Uint8Array;    // Salt used for derivation
  createdAt: number;   // Timestamp
}
```

---

## 12. Private & Encrypted Communities

### 12.1 Community Privacy Levels

| Level | Description |
|-------|-------------|
| **Public** | Open to everyone, no encryption |
| **Password-protected** | Requires a password to join; all content encrypted with derived key |
| **Invite-only** | Requires an invite link containing the encryption key |

### 12.2 Encrypted Community Data

When a community is encrypted, the following fields are stored as `EncryptedBlob`:

- Community `description`
- Post `title`, `content`
- Comment `content`
- Poll `question`, `description`

The `name` and `displayName` fields remain in plaintext for discoverability.

### 12.3 Invite Links

Invite links encode the community ID and encryption password as a URL fragment:

```
https://<host>/join/<communityId>#<base64-encoded-password>
```

The fragment (after `#`) is never sent to the server — it stays client-side.

---

## 13. Chat & Messaging

### 13.1 Direct Messages

Direct messages are end-to-end encrypted using RSA-OAEP key exchange. Each peer generates an RSA key pair on first use and shares the public key during the `chat-start` handshake.

#### Message Types

**`chat-start`** — Initiate a chat session:
```json
{ "type": "chat-start", "data": { "recipientId": "<peerId>" } }
```

**`chat-message`** — Send an encrypted message:
```json
{
  "type": "chat-message",
  "data": {
    "recipientId": "<peerId>",
    "encryptedForRecipient": "<base64-ciphertext>",
    "messageId": "<uuid>",
    "timestamp": 1708500000000
  }
}
```

**`chat-typing`** — Typing indicator:
```json
{ "type": "chat-typing", "data": { "recipientId": "<peerId>", "isTyping": true } }
```

**`chat-read`** — Mark messages as read:
```json
{ "type": "chat-read", "data": { "recipientId": "<peerId>" } }
```

### 13.2 Group Chat Rooms

Group chat rooms use AES-256-GCM with a shared room key. Room messages are broadcast via the relay:

**`chatroom-message`** — Group chat message:
```json
{
  "type": "chatroom-message",
  "data": {
    "roomId": "<roomId>",
    "data": { /* encrypted message payload */ }
  }
}
```

---

## 14. WebRTC Peer Connections

After peers discover each other via the WebSocket relay, they can establish direct WebRTC data channels to bypass the relay for lower latency.

### 14.1 Signalling Messages

All signalling goes through the WebSocket relay as broadcast messages.

**`rtc-offer`** — SDP offer:
```json
{
  "type": "rtc-offer",
  "data": {
    "peerId": "<sender>",
    "targetPeerId": "<recipient>",
    "sdp": "<SDP offer string>"
  }
}
```

**`rtc-answer`** — SDP answer:
```json
{
  "type": "rtc-answer",
  "data": {
    "peerId": "<sender>",
    "targetPeerId": "<recipient>",
    "sdp": "<SDP answer string>"
  }
}
```

**`rtc-ice`** — ICE candidate:
```json
{
  "type": "rtc-ice",
  "data": {
    "peerId": "<sender>",
    "targetPeerId": "<recipient>",
    "candidate": { /* RTCIceCandidate */ }
  }
}
```

### 14.2 Data Channel

Once the WebRTC connection is established, peers use a data channel named `interpoll` for direct message exchange. The message format is identical to WebSocket application-level messages (§4.4).

---

## 15. Snapshot Sync

Snapshot sync provides bulk state transfer for peers that are too far behind for incremental sync.

### 15.1 Protocol Flow

```
Peer A                              Peer B
  │                                    │
  │── snapshot-offer ─────────────────►│  (size, hash, metadata)
  │◄── snapshot-accept ────────────────│
  │── snapshot-chunk (1/N) ───────────►│
  │── snapshot-chunk (2/N) ───────────►│
  │── ...                             │
  │── snapshot-complete ──────────────►│  (final hash)
  │                                    │
```

### 15.2 Message Types

**`snapshot-offer`:**
```json
{
  "type": "snapshot-offer",
  "data": {
    "peerId": "<sender>",
    "size": 524288,
    "hash": "<sha256-hex>",
    "meta": {
      "postCount": 42,
      "communityCount": 5,
      "blockHeight": 128
    }
  }
}
```

**`snapshot-accept`:**
```json
{ "type": "snapshot-accept", "data": { "targetPeerId": "<offerer>", "peerId": "<acceptor>" } }
```

**`snapshot-chunk`:**
```json
{
  "type": "snapshot-chunk",
  "data": {
    "chunk": "<base64-data>",
    "chunkIndex": 0,
    "totalChunks": 10,
    "hash": "<chunk-sha256>"
  }
}
```

**`snapshot-cancel`:**
```json
{ "type": "snapshot-cancel", "data": { "targetPeerId": "<peerId>", "reason": "timeout" } }
```

---

## 16. Data Versioning

GunDB data is namespaced to allow schema migrations without breaking existing data.

### 16.1 Namespace Format

All GunDB paths are prefixed with a version string:

| Version | Prefix | Status |
|---------|--------|--------|
| v1 | _(none)_ | Legacy, still readable |
| v2 | `v2/` | Current default |

Example: `gun.get('v2/communities').get('<communityId>')`

### 16.2 Version Probing

Clients probe the GunDB relay to discover which data versions contain data. The active version is stored in `localStorage` under key `interpoll_data_version`.

### 16.3 Multi-Version Reads

Clients can optionally read from multiple data versions simultaneously (e.g., to surface v1 legacy content alongside v2 data).

---

## 17. User Identity & Pseudonyms

### 17.1 Device Identity

Each device generates a persistent anonymous identity:

| Field | Type | Description |
|-------|------|-------------|
| `deviceId` | `string` | SHA-256 fingerprint of browser/device properties |
| `userId` | `string` | Format: `anon_<timestampMs>`, generated on first visit |

Stored in `localStorage` under key `interpoll_user_id`.

### 17.2 Deterministic Pseudonyms

To provide consistent but anonymous display names, a deterministic pseudonym is generated for each `(userId, contextId)` pair using FNV-1a hashing:

```
pseudonym = "<adjective>-<color>-<animal>"
```

Example: `"bright-amber-sparrow"`

The same user gets the same pseudonym within a given context (post, community) but a different one in other contexts.

### 17.3 User Profiles

User profiles are stored in GunDB:

**Path:** `gun.get('v2/users').get('<userId>')`

| Field | Type | Description |
|-------|------|-------------|
| `displayName` | `string` | User-chosen display name |
| `bio` | `string` | Profile bio |
| `karma` | `number` | Accumulated score |
| `joinedAt` | `number` | Unix timestamp (ms) |

---

## 18. Search & Indexing API

### 18.1 `POST /api/index`

Submit content for server-side indexing.

**Request:**
```json
{
  "type": "post",
  "id": "post-xxx",
  "data": {
    "title": "Hello World",
    "content": "Post body text",
    "communityId": "c-general",
    "authorId": "anon_123",
    "createdAt": 1708500000000
  }
}
```

**Response:**
```json
{ "ok": true }
```

### 18.2 `GET /api/search`

Full-text search across indexed content.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `q` | `string` | Search query (required) |
| `type` | `string` | Filter by content type: `post`, `poll` |
| `community` | `string` | Filter by community ID |
| `limit` | `number` | Max results (default: 20) |
| `offset` | `number` | Pagination offset |

**Response:**
```json
{
  "results": [
    { "type": "post", "id": "post-xxx", "data": { ... }, "score": 0.95 }
  ],
  "total": 42
}
```

### 18.3 `GET /db/search`

Query the GunDB relay's radisk storage directly via REST.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `prefix` | `string` | GunDB path prefix (e.g., `v2/communities`) |
| `limit` | `number` | Max results |

**Response:**
```json
{
  "results": [
    { "soul": "v2/communities/c-general", "data": { ... } }
  ]
}
```

### 18.4 `GET /db/soul`

Fetch a specific GunDB record by its soul (path).

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `soul` | `string` | Full GunDB soul path |

**Response:**
```json
{ "soul": "v2/communities/c-general", "data": { ... } }
```

---

## 19. Content Moderation

### 19.1 Client-Side NSFW Detection

The client performs optional client-side NSFW content detection on uploaded images before submission. Flagged content is tagged but not blocked — moderation policy is left to community operators.

### 19.2 Moderation Actions

Community creators can perform moderation actions stored in GunDB:

| Action | Description |
|--------|-------------|
| Pin post | Pin a post to the top of the community feed |
| Remove content | Mark content as removed (soft delete) |
| Ban user | Add device ID to community ban list |

Moderation actions are signed with the moderator's Schnorr key pair for auditability.
