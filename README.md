# InterPoll

A decentralised polling and community platform. Votes are recorded on a local blockchain, poll data lives in a distributed database (GunDB), and peers find each other through a lightweight WebSocket relay. Everything works offline — sync happens when a connection is available. Data is resilient by design: as soon as one peer comes back online, the full dataset is restored.

<img width="1918" height="966" alt="InterPoll screenshot" src="https://github.com/user-attachments/assets/31717176-eb42-43b2-8200-8da9cf022550" />

## Architecture

| Component | Purpose |
|-----------|---------|
| **Vue 3 Client** | SPA with Ionic UI, local blockchain, Schnorr signatures, E2E encryption |
| **WebSocket Relay** | Real-time message fan-out, vote authorisation, audit receipts |
| **GunDB Relay** | Persistent, eventually-consistent graph database with REST query API |
| **Headless Peer** | Always-on Node.js peer for data persistence and replication |

## Live Instance

The production client is deployed at **[endless.sbs](https://endless.sbs)** and connects to the official relay servers on Render.

## Community Backend

The relay servers included in this repository (`community-relay-server/` and `gun-relay-server/`) are the **community edition** of the InterPoll backend. They implement the full [TurkeyLuck protocol specification](spec.md) and are fully compatible with the client.

The production backend runs a hardened, hand-coded implementation that is withheld for security reasons. Community edition releases may lag behind production, but **the protocol specification (`spec.md`) is always published and up to date**, so anyone can build a compatible server.

## Quick Start

### Prerequisites

- Node.js ≥ 18
- npm

### Run Everything (development)

```bash
# Install client dependencies
npm install

# Install relay server dependencies
cd community-relay-server && npm install && cd ..
cd gun-relay-server && npm install && cd ..

# Start all services (requires tmux)
./run.sh
```

Or start each service separately:

```bash
# Terminal 1 — Vite dev server
npm run dev

# Terminal 2 — WebSocket relay (port 8080)
cd community-relay-server && node community-relay-server.js

# Terminal 3 — GunDB relay (port 8765)
cd gun-relay-server && node gun-relay.js
```

Then open `http://localhost:5173` and point the client at your local relays via **Settings → Relay Configuration**.

### Headless Peer

Run a headless peer to keep data alive when no browser is open:

```bash
node peer.js --ws ws://localhost:8080 --gun http://localhost:8765/gun --api http://localhost:8080
```

### Build for Production

```bash
npm run build   # outputs to dist/
```

## Configuration

The client defaults to the official Render relay servers. Override at runtime via the Settings page, or set `localStorage` key `interpoll_relay_config`:

```json
{
  "websocket": "wss://your-relay.example.com",
  "gun": "https://your-gun-relay.example.com/gun",
  "api": "https://your-relay.example.com"
}
```

## Protocol Specification

The full protocol spec is at **[spec.md](spec.md)**. It covers:

- GunDB data schema (communities, polls, posts, comments, images)
- WebSocket relay protocol (message types, lifecycle, caching)
- Local blockchain audit chain (block structure, hashing, signing, sync)
- Nostr-compatible signed events (NIP-01)
- End-to-end encryption (AES-256-GCM, private communities)
- P2P encrypted chat and WebRTC signalling
- Snapshot sync for bulk state transfer
- HTTP API endpoints (vote authorisation, search, health checks)
- Server discovery and mesh federation

## Project Structure

```
├── src/                        # Vue 3 client application
│   ├── services/               # Core services (gun, websocket, crypto, chat, etc.)
│   ├── stores/                 # Pinia state management
│   ├── composables/            # Vue composables
│   ├── views/                  # Page components
│   ├── components/             # Reusable UI components
│   ├── types/                  # TypeScript type definitions
│   └── utils/                  # Utility functions
├── community-relay-server/     # Community edition WebSocket relay
├── gun-relay-server/           # Community edition GunDB relay
├── peer.js                     # Headless replication peer
├── spec.md                     # Protocol specification
└── run.sh                      # Development launcher (tmux)
```

## License

MIT
