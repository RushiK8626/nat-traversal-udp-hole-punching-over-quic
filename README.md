# NAT Traversal with UDP Hole Punching

A complete NAT traversal implementation using UDP hole punching with QUIC transport, relay fallback, and comprehensive metrics.

## Features

- **NAT Classification**: Detects full cone, restricted cone, port-restricted, and symmetric NAT
- **UDP Hole Punching**: Simultaneous hole punching with retry logic
- **QUIC Transport**: Using `aioquic` with 0-RTT session resumption
- **Relay Fallback**: WebSocket-based relay when hole punching fails
- **TLS Authentication**: QUIC built-in TLS 1.3 certificate-based authentication
- **Metrics Dashboard**: Real-time metrics via HTTP endpoint

## Architecture

```
┌─────────────────┐                    ┌─────────────────┐
│     Peer A      │                    │     Peer B      │
│                 │                    │                 │
│  ┌───────────┐  │                    │  ┌───────────┐  │
│  │ NAT Class │  │                    │  │ NAT Class │  │
│  └─────┬─────┘  │                    │  └─────┬─────┘  │
│        │        │                    │        │        │
│  ┌─────▼─────┐  │   UDP Hole Punch   │  ┌─────▼─────┐  │
│  │   Hole    │◄─┼────────────────────┼─►│   Hole    │  │
│  │   Punch   │  │                    │  │   Punch   │  │
│  └─────┬─────┘  │                    │  └─────┬─────┘  │
│        │        │                    │        │        │
│  ┌─────▼─────┐  │   QUIC Streams     │  ┌─────▼─────┐  │
│  │   QUIC    │◄─┼────────────────────┼─►│   QUIC    │  │
│  │ (aioquic) │  │  Stream 0: Control │  │ (aioquic) │  │
│  │           │  │  Stream 1: Chat    │  │           │  │
│  │           │  │  Stream 2: Files   │  │           │  │
│  └───────────┘  │                    │  └───────────┘  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │         ┌─────────────────┐          │
         └────────►│   Rendezvous    │◄─────────┘
                   │     Server      │
                   │                 │
                   │  - STUN Probes  │
                   │  - WS Signaling │
                   │  - Peer Coord   │
                   │  - Relay Mode   │
                   └─────────────────┘
```

## Project Structure

```
nat/
├── server/
│   └── rendezvous.py      # STUN probes + WebSocket signaling + tokens
├── peer/
│   ├── nat_classifier.py  # NAT type detection
│   ├── hole_punch.py      # UDP hole punching logic
│   ├── quic_peer.py       # QUIC with aioquic + 0-RTT
│   ├── relay.py           # WebSocket relay fallback
│   ├── auth.py            # Legacy token auth module (not used in main flow)
│   ├── metrics.py         # Metrics collection + HTTP endpoint
│   └── main.py            # Main orchestrator
├── certs/                 # TLS certificates (generated)
├── scripts/
│   └── gen_certs.py       # Certificate generation
├── requirements.txt
├── demo.bat               # Windows demo script
└── demo.sh                # Linux/Mac demo script
```

## Installation

```bash
pip install -r requirements.txt
```

## Command Reference (Local + Docker)

Use this section as a copy/paste checklist for setup and day-to-day usage.

### Local setup (PowerShell)

```powershell
# from project root
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/gen_certs.py
```

### Local setup (bash)

```bash
# from project root
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 scripts/gen_certs.py
```

### Local run (3 terminals)

Terminal 1 (server):

```bash
python server/rendezvous.py --host 0.0.0.0
```

Terminal 2 (alice listener):

```bash
python peer/main.py --server 127.0.0.1 --peer-id alice --metrics-port 9090
```

Terminal 3 (bob connector):

```bash
python peer/main.py --server 127.0.0.1 --peer-id bob --connect alice --metrics-port 9091
```

### Local usage commands (inside peer prompt)

```text
hello
/stats
/file ./somefile.txt
/quit
```

### Local metrics commands

```bash
curl http://localhost:9090/metrics
curl http://localhost:9091/metrics
curl http://localhost:9090/metrics/summary
```

### Docker setup and run (PowerShell)

```powershell
# from project root
New-Item -ItemType Directory -Force docker_data/bob_send | Out-Null
New-Item -ItemType Directory -Force docker_data/alice_inbox | Out-Null
Set-Content -Path docker_data/bob_send/test.txt -Value "hello from bob via quic file transfer"

docker compose down --remove-orphans
docker compose up -d --build rendezvous alice
docker compose run --rm bob
```

Inside Bob prompt:

```text
/file /send/test.txt
/stats
```

Verify on host:

```powershell
Get-ChildItem docker_data/alice_inbox
Get-ChildItem docker_data/alice_inbox/alice
Get-Content docker_data/alice_inbox/alice/test.txt
```

### Docker useful commands

```powershell
docker compose logs -f rendezvous
docker compose logs -f alice
docker compose logs --tail=120 alice
docker compose ps
docker compose down
```

## Quick Start

### 1. Generate Certificates

```bash
python scripts/gen_certs.py
```

### 2. Start Rendezvous Server

```bash
python server/rendezvous.py
```

Server listens on:
- UDP 3478, 3479: STUN probes
- WebSocket 8765: Signaling

### 3. Start Peer A (Listener)

```bash
python peer/main.py --server <server_ip> --peer-id alice
```

### 4. Start Peer B (Connector)

```bash
python peer/main.py --server <server_ip> --peer-id bob --connect alice
```

## Docker Compose: Exact File Transfer Test

This repository includes a Docker Compose setup that can be used to verify end-to-end file transfer.

### What this setup mounts

- `./docker_data/bob_send` -> `/send` inside Bob container (source files to send)
- `./docker_data/alice_inbox` -> `/app/received_files` inside Alice container (received files)

Received files are saved under:

- `/app/received_files/<peer_id>/<filename>` inside container
- `docker_data/alice_inbox/<peer_id>/<filename>` on host

### 1. Prepare folders and test file (PowerShell)

```powershell
New-Item -ItemType Directory -Force docker_data/bob_send | Out-Null
New-Item -ItemType Directory -Force docker_data/alice_inbox | Out-Null
Set-Content -Path docker_data/bob_send/test.txt -Value "hello from bob via quic file transfer"
```

### 2. Start rendezvous + Alice

```powershell
docker compose down --remove-orphans
docker compose up -d --build rendezvous alice
```

Optional log watch:

```powershell
docker compose logs -f alice
```

### 3. Start Bob interactively and send file

```powershell
docker compose run --rm bob
```

Then inside Bob's interactive prompt:

```text
/file /send/test.txt
/stats
```

### 4. Verify file on host

```powershell
Get-ChildItem docker_data/alice_inbox
Get-ChildItem docker_data/alice_inbox/alice
Get-Content docker_data/alice_inbox/alice/test.txt
```

### 5. Stop services

```powershell
docker compose down
```

### Expected successful logs

- Bob: `*** Connected to alice (direct mode) ***`
- Bob: `File sent: test.txt (...)`
- Alice: `File transfer complete: test.txt`
- Alice: `*** File received: test.txt (...) -> received_files/alice/test.txt ***`

### Important note about relay mode

If logs show relay mode (`Connected ... (relay mode)`), `/file` is intentionally unavailable.
File transfer works only in direct QUIC mode.

## Usage

### Command Line Options

```bash
python peer/main.py [OPTIONS]

Options:
  --peer-id TEXT       Unique peer identifier (default: random)
  --server TEXT        Rendezvous server address (required)
  --ws-port INT        WebSocket port (default: 8765)
  --stun-port-1 INT    First STUN port (default: 3478)
  --stun-port-2 INT    Second STUN port (default: 3479)
  --metrics-port INT   Metrics HTTP port (default: 9090)
  --connect TEXT       Target peer ID to connect to
  --cert TEXT          TLS certificate file
  --key TEXT           TLS private key file
```

### Interactive Commands

Once connected:
- Type messages and press Enter to chat
- `/stats` - Show connection statistics
- `/file <path>` - Send a file (direct mode only)
- `/quit` - Exit

### Metrics

Access metrics at `http://localhost:9090/`:
- `/` - HTML dashboard
- `/metrics` - Raw JSON
- `/metrics/summary` - Condensed summary

## NAT Classification

The classifier sends UDP probes to both STUN ports and compares mapped addresses:

| Probe 1 | Probe 2 | Classification |
|---------|---------|----------------|
| Same IP + Same Port | Same IP + Same Port | Full Cone |
| Same IP + Different Port (small diff) | - | Port Restricted |
| Same IP + Different Port (large diff) | - | Symmetric |
| Different IP | - | Symmetric |

## Hole Punching Strategy

1. Both peers receive each other's mapped address via WebSocket
2. Simultaneously send UDP packets every 200ms
3. Continue for up to 3 seconds
4. First peer to receive response confirms the hole

If both peers have symmetric NAT, hole punching is skipped and relay mode is used.

## QUIC Streams

| Stream ID | Purpose | Notes |
|-----------|---------|-------|
| 0 | Control/Ping | RTT measurement every 5s |
| 4 | Chat/Data | Text messages |
| 8 | File Transfer | Binary data (disabled in relay) |

## 0-RTT Resumption

Session tickets are cached in `.session_tickets_<peer_id>.pkl`. Subsequent connections reuse tickets for faster handshakes.

Metrics show:
- `is_0rtt: true` when resumption succeeded
- Connection time difference: ~50-100ms savings

## Relay Mode

When hole punching fails:
1. Both peers connect to server via WebSocket
2. Server proxies messages between them
3. 4KB payload limit (no file transfers)
4. Metrics flag `using_relay: true`

## QUIC TLS Authentication

Connection authentication flow:
1. Peers exchange candidate addresses via rendezvous server signaling
2. Peers establish QUIC directly over the punched UDP path
3. QUIC performs built-in TLS 1.3 handshake with certificate verification
4. Connection proceeds only if certificate validation succeeds

## Environment Variables

No token-secret environment variable is required for peer authentication.

## Testing Locally

The demo works on localhost. For real NAT testing:

1. Run server on a public VPS
2. Run peers behind different NATs
3. Observe NAT classification and hole punch behavior

Simulate NAT with iptables:
```bash
# Port-restricted NAT simulation
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
```

## Metrics Example

```json
{
  "peer_id": "alice",
  "connections": {
    "bob": {
      "nat_type": "full_cone",
      "hole_punch_success": true,
      "hole_punch_time_ms": 245.3,
      "using_relay": false,
      "is_0rtt": true,
      "rtt": {
        "last_ms": 52.1,
        "avg_ms": 48.7,
        "min_ms": 45.2,
        "max_ms": 67.3
      },
      "bytes": {
        "total_sent": 15234,
        "total_received": 12891
      }
    }
  }
}
```

## Demo & Testing

### Run Tests

```bash
python tests.py
```

Runs comprehensive tests:
- File structure validation
- Dependency verification
- NAT classifier testing
- QUIC TLS config testing
- Metrics endpoint testing

### Interactive Demo

```bash
python demo_interactive.py
```

Step-by-step guided demo showing:
- Server startup
- Peer registration
- NAT classification
- QUIC TLS handshake
- Hole punch attempt
- Relay fallback
- Message sending
- Metrics dashboard

### Manual Testing

**Terminal 1 - Start Server:**
```bash
python server/rendezvous.py --host 127.0.0.1
```

**Terminal 2 - Start Alice (Listener):**
```bash
python peer/main.py --server 127.0.0.1 --peer-id alice --metrics-port 9090
```

**Terminal 3 - Start Bob (Connector):**
```bash
python peer/main.py --server 127.0.0.1 --peer-id bob --connect alice --metrics-port 9091
```

**Check Metrics:**
```bash
# Alice metrics
curl http://localhost:9090/metrics

# Bob metrics  
curl http://localhost:9091/metrics

# Summary view
curl http://localhost:9090/metrics/summary
```

## Real-World Scenario

To test with actual NAT:

1. **Deploy server to VPS**
   ```bash
   ssh user@vps.example.com
   python3 server/rendezvous.py --host 0.0.0.0 --ws-port 8765
   ```

2. **Run peers behind different NATs**
   ```bash
   python3 peer/main.py --server vps.example.com --peer-id alice
   python3 peer/main.py --server vps.example.com --peer-id bob --connect alice
   ```

3. **Observe results**
   - With full cone NAT: Hole punch succeeds, direct P2P
   - With port-restricted NAT: Hole punch succeeds in most cases
   - With symmetric NAT: Falls back to relay
   - With symmetric-to-symmetric: Always uses relay

## Architecture Diagrams

### NAT Detection Flow

```
Peer A                              Server (STUN)
  |                                     |
  +--- UDP probe (port 1) ----------->  |
  |                                     |
  |  [Server responds with]             |
  |  mapped_ip: 1.2.3.4                 |
  |  mapped_port: 12345                 |
  |                                     |
  +--- UDP probe (port 2) ----------->  |
  |                                     |
  |  [Server responds with]             |
  |  mapped_ip: 1.2.3.4                 |
  |  mapped_port: 12345                 |
  |                                     |
  Compare results:
  - Same IP + Same Port = Full Cone
  - Same IP + Different Port = Port Restricted
  - Different results = Symmetric
```

### Hole Punch Flow (Simultaneous)

```
Peer A                         Peer B
  |                              |
  |                         (gets A's addr from server)
  |                              |
  +-- UDP packet ------>         |
  |                              |
  |  <------ UDP packet --+
  |                              |
  |  (both send simultaneously,  |
  |   creating UDP entries in    |
  |   their NATs that allow      |
  |   return traffic)            |
  |                              |
  +-- Establish QUIC over punched hole
```

### Relay Fallback Flow

```
Peer A                Server (Relay)              Peer B
  |                        |                       |
  +--- WS relay_request --->|                       |
  |                        |<--- relay_request ----+
  |                        |
  |                    [Establish relay session]
  |                        |
  +-- WS relay_frame ----->|--- relay_frame ----->+
  |                        |
  |<----- relay_frame -----+--- WS relay_frame ----+
  |                        |
  (Messages proxied through server)
```

## Performance Notes

### Direct P2P (Hole Punch Success)
- Latency: Typically < 50ms (depends on network)
- Throughput: Limited only by network capacity
- Best case: Both peers have full-cone or restricted-cone NAT

### Relay Mode
- Latency: + 50-100ms (server hop overhead)
- Throughput: Limited by server bandwidth
- Used when: Symmetric NAT detected or hole punch fails
- Payload: Limited to 4KB per message (no file transfers)

### 0-RTT Resumption
- On reconnect: 10-20ms faster than initial handshake
- Uses cached session tickets from `~/.session_tickets_<peer_id>.pkl`
- Visible in metrics: `"is_0rtt": true`

## Troubleshooting

### "Probe error: [WinError 10022]"
- Windows socket configuration issue
- Fix: Ensure UDP ports 3478, 3479 are not in use
- Alternative: Use different ports with `--stun-port-1` and `--stun-port-2`

### "Failed to get responses from STUN server"
- Server not running or unreachable
- Check: Server is listening on correct host/port
- Test: `telnet <server> 8765` for WebSocket port

### "Hole punch FAILED"
- Expected on localhost (both peers same IP)
- Expected with symmetric-to-symmetric NAT
- Normal fallback: Relay mode is activated

### "Connection timeout"
- Firewall blocking UDP ports
- Check: UFW, iptables, Windows Firewall
- Allow: UDP traffic on configured ports

### "File transfer complete" in logs but file not found on host
- Verify you rebuilt after latest changes: `docker compose up -d --build rendezvous alice`
- Verify expected host path: `docker_data/alice_inbox/alice/<filename>`
- Verify connection mode is direct, not relay
- Check Alice logs: `docker compose logs --tail=120 alice`

## License

MIT
