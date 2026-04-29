"""
NAT Traversal Peer - Main Orchestrator
Ties together all components:
- NAT classification
- Authentication with rendezvous server
- Hole punching
- QUIC transport with 0-RTT
- Relay fallback
- QUIC TLS authentication
- Metrics collection
"""

import asyncio
import argparse
import json
import base64
import logging
import os
import time
import socket
import uuid
import websockets
from pathlib import Path
from typing import Optional, Tuple

from peer.nat_classifier import NATClassifier, NATClassificationResult
from peer.hole_punch import BidirectionalHolePuncher, HolePunchResult
from peer.quic_peer import QuicPeer, QuicPeerProtocol
from peer.relay import RelayClient, RelayPeerAdapter
from peer.metrics import MetricsCollector, MetricsServer
from common.auth import TokenAuthClient, ConnectionToken

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)
logger = logging.getLogger('main')


class PeerNode:
    """
    Main peer node that orchestrates NAT traversal and connection establishment.
    """
    
    def __init__(self, peer_id: str, server_host: str, server_ws_port: int = 8765,
                 server_stun_port_1: int = 3478, server_stun_port_2: int = 3479,
                 cert_file: str = None, key_file: str = None,
                 metrics_port: int = 9090):
        self.peer_id = peer_id
        self.server_host = server_host
        self.server_ws_port = server_ws_port
        self.server_stun_port_1 = server_stun_port_1
        self.server_stun_port_2 = server_stun_port_2
        self.metrics_port = metrics_port
        
        # Certificate paths
        base_dir = Path(__file__).parent.parent / 'certs'
        self.cert_file = cert_file or str(base_dir / 'cert.pem')
        self.key_file = key_file or str(base_dir / 'key.pem')
        
        # Ensure certs exist
        if not os.path.exists(self.cert_file):
            logger.info("Generating self-signed certificate...")
            os.makedirs(base_dir, exist_ok=True)
            
            from scripts.gen_certs import generate_certificate
            generate_certificate(
                cert_file=self.cert_file,
                key_file=self.key_file,
                common_name=peer_id,
                days_valid=365,
                key_type='rsa',
                key_size=2048,
                san_ips=['127.0.0.1', self._get_local_ip()],
                san_dns=['localhost']
            )
        
        # Components
        self.classifier = NATClassifier(
            server_host, server_stun_port_1, server_stun_port_2
        )
        self.metrics = MetricsCollector(peer_id)
        self.metrics_server = MetricsServer(self.metrics, port=metrics_port)
        self.auth_client = TokenAuthClient(peer_id, f"ws://{server_host}:{server_ws_port}")
        
        # State
        self.nat_result: Optional[NATClassificationResult] = None
        self.local_socket: Optional[socket.socket] = None
        self.local_port: int = 0
        self.websocket = None
        self.protocol: Optional[QuicPeerProtocol] = None
        self._quic_peer: Optional[QuicPeer] = None  # Keep alive to prevent GC
        self.relay_client: Optional[RelayClient] = None
        self.using_relay = False
        self.relay_target_peer_id: Optional[str] = None
        
        # Callbacks
        self.on_chat_message = None
        self.on_file_received = None
        self.on_connected = None

        self._ws_lock = asyncio.Lock()
        self._socket_lock = asyncio.Lock()
        self._quic_lock = asyncio.Lock()
        self._protocol_lock = asyncio.Lock() 
        self._relay_lock = asyncio.Lock()

    async def _send_relay_frame(self, target_peer_id: str, payload: bytes) -> bool:
        """Send a relay frame via the signalling websocket (fallback path for listener peers)."""
        if len(payload) > 4096:
            logger.warning("Relay payload too large, dropping")
            return False

        payload_b64 = base64.b64encode(payload).decode()
        try:
            async with self._ws_lock:
                if not self._is_websocket_open():
                    if not await self._reconnect_signalling_locked():
                        return False
                await self.websocket.send(json.dumps({
                    'type': 'relay_frame',
                    'target': target_peer_id,
                    'payload': payload_b64
                }))
            return True
        except Exception as e:
            logger.error(f"Failed to send relay frame via signalling websocket: {e}")
            return False

    def _handle_signalling_relay_frame(self, source_peer: str, payload_b64: str) -> None:
        """Handle relay frames received on the signalling websocket."""
        try:
            payload = base64.b64decode(payload_b64)
            msg = json.loads(payload.decode())
            msg_type = msg.get('type')

            if msg_type == 'chat' and self.on_chat_message:
                self.on_chat_message(msg.get('from', source_peer), msg.get('text', ''))
            elif msg_type == 'control' and msg.get('control_type') == 'ping':
                asyncio.create_task(self._send_relay_frame(source_peer, json.dumps({
                    'type': 'control',
                    'control_type': 'pong',
                    'from': self.peer_id,
                    'seq': msg.get('seq')
                }).encode()))
        except Exception as e:
            logger.error(f"Error handling signalling relay frame: {e}")
    
    def _is_websocket_open(self) -> bool:
        """Check if websocket is open and usable."""
        if self.websocket is None:
            return False
        # A connection is open if it exists and hasn't been explicitly closed
        try:
            # Check if connection has a valid state by testing the object
            return hasattr(self.websocket, 'transport') and self.websocket.transport is not None
        except:
            return False

    async def _request_token_on_existing_ws(self, target_peer_id: str) -> Optional[ConnectionToken]:
        """Request auth token reusing the existing signalling websocket."""
        for attempt in range(2):
            try:
                async with self._ws_lock:
                    if not self.websocket or not self._is_websocket_open():
                        if not await self._reconnect_signalling_locked():
                            return None

                    token = await self.auth_client.request_token_on_connection(
                        self.websocket, target_peer_id
                    )
                    return token

            except websockets.exceptions.ConnectionClosed as e:
                logger.warning(f"WebSocket closed while requesting token (attempt {attempt+1}): {e}")
                if attempt == 1:
                    logger.error("Token request failed after reconnect, giving up")
                    return None
                # Reconnect and retry
                async with self._ws_lock:
                    if not await self._reconnect_signalling_locked():
                        return None
                # loop continues to retry

            except Exception as e:
                logger.error(f"Unexpected error requesting token: {e}")
                return None

        return None

    async def _ensure_local_socket(self, preferred_port: Optional[int] = None) -> None:
        async with self._socket_lock:
            if self.local_socket is not None:
                try:
                    self.local_socket.getsockname() 
                    return  # Socket is still valid, no need to recreate
                except OSError:
                    logger.warning("Existing local socket is no longer valid, recreating...")
                    self.local_socket.close()
                    self.local_socket = None
                    self.local_port = 0

            bind_port = preferred_port if preferred_port is not None else self.local_port

            for attempt in range(3):
                try:
                    self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.local_socket.bind(('0.0.0.0', bind_port or 0))
                    self.local_socket.setblocking(False)
                    self.local_port = self.local_socket.getsockname()[1]
                    logger.info(f"Rebound local UDP socket on port: {self.local_port}")
                    return
                except OSError as e:
                    logger.warning(f"Socket bind failed (attempt {attempt+1}): {e}")
                    self.local_socket = None
                    bind_port = 0  # fall back to ephemeral on retry
                    await asyncio.sleep(0.5)

            raise OSError(f"Failed to bind UDP socket after retries")
    
    def _get_local_ip(self) -> str:
        """Get the local/private IP address (LAN IP, not public)"""
        import psutil
        
        try:
            # Get all network interfaces and their addresses
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    # Only check IPv4 addresses
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if ip and not ip.startswith('127.') and ip != '0.0.0.0':
                            # Prefer private IPs (10.x, 172.16-31.x, 192.168.x)
                            if (ip.startswith('10.') or 
                                ip.startswith('192.168.') or
                                (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
                                return ip
            
            # Fallback: use socket method (may return public IP if no private IP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # Google DNS
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.warning(f"Could not determine local IP: {e}")
            return None
    
    async def start(self):
        """Start the peer node"""
        logger.info(f"[STARTUP] Initializing peer: {self.peer_id}")
        
        # Start metrics server
        logger.info(f"[STARTUP] Starting metrics HTTP server on port {self.metrics_port}...")
        self.metrics_server.start()
        
        # Create local UDP socket for NAT probing and hole punching
        logger.info(f"[STARTUP] Binding local UDP socket for NAT classification...")
        self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow quick reuse of port (important for localhost testing on Windows)
        self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.local_socket.bind(('0.0.0.0', 0))
        self.local_socket.setblocking(False)
        self.local_port = self.local_socket.getsockname()[1]
        logger.info(f"[SOCKET] Bound to local port: {self.local_port}")
        
        # Classify NAT type
        logger.info(f"[NAT] Classifying NAT type via {self.server_host}:{self.server_stun_port_1}/{self.server_stun_port_2}...")
        self.nat_result = await self.classifier.classify_with_socket(
            self.peer_id, self.local_socket
        )
        
        if self.nat_result:
            logger.info(f"[NAT] Classification complete: Type={self.nat_result.nat_type} | Mapped={self.nat_result.mapped_addr_1[0]}:{self.nat_result.mapped_addr_1[1]} | Confidence={self.nat_result.confidence}")
        else:
            logger.warning("[NAT] Classification failed, proceeding with unknown NAT type")
        
        # Connect to rendezvous server
        logger.info(f"[WS] Connecting to rendezvous server: ws://{self.server_host}:{self.server_ws_port}...")
        ws_url = f"ws://{self.server_host}:{self.server_ws_port}"
        try:
            self.websocket = await websockets.connect(ws_url)
            logger.info(f"[WS] Connected to rendezvous server")
        except Exception as e:
            logger.error(f"[WS] Failed to connect: {e}")
            raise

        await self._register_with_server()
        
        local_ip = self._get_local_ip() or 'N/A'
        nat_type = self.nat_result.nat_type if self.nat_result else 'unknown'
        nat_confidence = self.nat_result.confidence if self.nat_result else 'N/A'
        mapped_ip = f"{self.nat_result.mapped_addr_1[0]}:{self.nat_result.mapped_addr_1[1]}" if self.nat_result and self.nat_result.mapped_addr_1 else 'N/A'

        local_addr   = f"{local_ip}:{self.local_port}"
        signal_addr  = f"ws://{self.server_host}:{self.server_ws_port}"
        metrics_addr = f"http://localhost:{self.metrics_port}"
        nat_info     = f"{nat_type}  (confidence: {nat_confidence})"

        rows = [
            ("Peer ID",           self.peer_id),
            ("NAT Type",          nat_info),
            ("Public Address",    mapped_ip),
            ("Local Address",     local_addr),
            ("Signaling Server",  signal_addr),
            ("Metrics Endpoint",  metrics_addr),
        ]

        label_w = max(len(r[0]) for r in rows)
        value_w = max(len(r[1]) for r in rows)
        total_w = label_w + value_w + 5  # 2 borders + 3 separators

        title      = "PEER INFORMATION"
        header     = "PEER STARTED - READY FOR CONNECTIONS"
        title      = "PEER INFORMATION"
        header     = "PEER STARTED - READY FOR CONNECTIONS"
        top        = f"┌{'─' * (total_w)}┐"
        mid_div    = f"├{'─' * (label_w + 2)}┬{'─' * (value_w + 2)}┤"
        bottom     = f"└{'─' * (label_w + 2)}┴{'─' * (value_w + 2)}┘"
        title_row  = f"│ {title:^{total_w - 2}} │"  
        title_div  = f"├{'─' * (total_w)}┤"

        print()
        print(f"{'=' * total_w}")
        print(f"{header:^{total_w}}")
        print(f"{'=' * total_w}")
        print(top)
        print(title_row)
        print(title_div)
        for i, (label, value) in enumerate(rows):
            print(f"│ {label:<{label_w}} │ {value:<{value_w}} │")
            if i < len(rows) - 1:
                print(mid_div)
        print(bottom)
        print(f"{'=' * total_w}")
        print(f"  ✓ UDP Socket : {self.local_port}")
        print(f"  ✓ NAT        : {nat_type} ({nat_confidence})")
        print(f"  ✓ Metrics    : {metrics_addr}/")
        print(f"  ✓ Ready to accept connections (peer-to-peer or relay)")
        print(f"{'=' * total_w}")
        print()
        
        return self

    async def _register_with_server(self):
        """Register this peer on the signalling websocket."""
        async with self._ws_lock:
            await self._register_with_server_locked()
    
    async def _register_with_server_locked(self):
        """Internal: register without acquiring lock (assumes caller holds _ws_lock)."""
        # Get local IP address
        local_ip = self._get_local_ip()

        if not self.websocket:
            raise RuntimeError("WebSocket is not connected")

        await self.websocket.send(json.dumps({
            'type': 'register',
            'peer_id': self.peer_id,
            'mapped_addr': list(self.nat_result.mapped_addr_1) if self.nat_result else None,
            'local_addr': [local_ip, self.local_port],  # Private IP for hairpin NAT
            'nat_type': self.nat_result.nat_type if self.nat_result else 'unknown'
        }))

        response = await self.websocket.recv()
        data = json.loads(response)
        logger.info(f"Registered with server: {data}")

    async def _reconnect_signalling(self) -> bool:
        """Reconnect and re-register signalling websocket after disconnect."""
        async with self._ws_lock:
            return await self._reconnect_signalling_locked()
    
    async def _reconnect_signalling_locked(self) -> bool:
        """Internal: reconnect without acquiring lock (assumes caller holds _ws_lock)."""
        if self._is_websocket_open():
            return True  # already reconnected by another coroutine
        ws_url = f"ws://{self.server_host}:{self.server_ws_port}"
        try:
            self.websocket = await websockets.connect(ws_url)
            await self._register_with_server_locked()
            logger.info("Reconnected signalling websocket")
            return True
        except Exception as e:
            logger.error(f"Failed to reconnect signalling websocket: {e}")
            return False
    
    async def connect_to_peer(self, target_peer_id: str) -> bool:
        """
        Connect to another peer.
        
        Flow:
        1. Request authentication token from server for target peer
        2. Send connect request via signalling server
        3. Receive peer's mapped address
        4. Attempt hole punching
        5. If fails, fall back to relay
        6. Establish QUIC connection with TLS handshake
        """
        logger.info(f"[CONNECT] Initiating connection to peer: {target_peer_id}")

        # Request authentication token
        logger.debug(f"[CONNECT] Requesting auth token for {target_peer_id}...")
        token = await self._request_token_on_existing_ws(target_peer_id)
        if not token:
            logger.error(f"[CONNECT] Failed to obtain auth token, cannot proceed")
            return False
        logger.debug(f"[CONNECT] Auth token obtained, expires in {token.seconds_remaining()}s")

        # Start metrics tracking
        self.metrics.start_connection(target_peer_id)
        if self.nat_result:
            self.metrics.record_nat_classification(
                target_peer_id,
                self.nat_result.nat_type,
                self.nat_result.confidence,
                self.nat_result.mapped_addr_1
            )
        
        # Send connect request (peer authentication is done by QUIC TLS)
        try:
            logger.debug(f"[CONNECT] Sending connect request via signalling...")
            async with self._ws_lock:
                if not self._is_websocket_open():
                    # Use unlocked version to avoid nested lock acquisition
                    if not await self._reconnect_signalling_locked():
                        logger.error("[CONNECT] Failed to reconnect websocket")
                        return False
                
                await self.websocket.send(json.dumps({
                    'type': 'connect_request',
                    'peer_a_id': self.peer_id,
                    'peer_b_id': target_peer_id,
                    'token': token.token
                }))

                # Wait for peer info
                logger.debug(f"[CONNECT] Waiting for peer info from server...")
                response = await self.websocket.recv()
        except websockets.exceptions.ConnectionClosed as e:
            logger.warning(f"[CONNECT] Signalling websocket closed: {e}")
            await self._reconnect_signalling()
            return False

        peer_info = json.loads(response)
        
        if peer_info.get('type') == 'connect_failed':
            logger.warning(f"[CONNECT] Server denied connection: {peer_info.get('reason')}")
            return False
        
        if peer_info.get('type') != 'peer_info':
            logger.error(f"[CONNECT] Unexpected response type: {peer_info.get('type')}")
            return False
        
        peer_addr = tuple(peer_info['mapped_addr']) if peer_info.get('mapped_addr') else None
        peer_local_addr = tuple(peer_info.get('local_addr')) if peer_info.get('local_addr') else None
        peer_nat_type = peer_info.get('nat_type', 'unknown')

        if not peer_addr:
            logger.warning(f"[CONNECT] No mapped address from {target_peer_id}, cannot attempt direct connection")
            logger.info("[CONNECT] Falling back to relay mode")
            return await self._establish_relay(target_peer_id)

        # Detect hairpin NAT: same public IP AND both on same local subnet (192.168.x or 10.x)
        my_public_ip = self.nat_result.mapped_addr_1[0] if self.nat_result else None
        peer_public_ip = peer_addr[0]

        # Only use local addr if:
        # 1. Same public IP (behind same NAT)
        # 2. Peer has local_addr (not None)
        # 3. Both are on recognizable private ranges (not tunnel/container networks like 10.255.x.x)
        same_public_ip = my_public_ip == peer_public_ip
        peer_on_private_net = peer_local_addr and (
            peer_local_addr[0].startswith('192.168.') or
            (peer_local_addr[0].startswith('10.') and not peer_local_addr[0].startswith('10.255.'))
        )
        use_local_addr = same_public_ip and peer_on_private_net and peer_local_addr

        if use_local_addr:
            logger.info(f"[HAIRPIN] Detected same public IP: {my_public_ip}")
            logger.info(f"[HAIRPIN] Using local address: {peer_local_addr[0]}:{peer_local_addr[1]} instead of {peer_addr[0]}:{peer_addr[1]}")
            actual_addr = peer_local_addr
        else:
            logger.debug(f"[CONNECT] Using public address: {peer_addr[0]}:{peer_addr[1]}")
            actual_addr = peer_addr

        logger.info(f"[CONNECT] Target peer {target_peer_id} | NAT={peer_nat_type} | Address={actual_addr[0]}:{actual_addr[1]}")
        if peer_local_addr and not use_local_addr:
            logger.debug(f"[CONNECT]   (Local address available but not used: {peer_local_addr[0]}:{peer_local_addr[1]})") 
        
        # Wait for synchronized punch start time if provided
        punch_start_time = peer_info.get('punch_start_time')
        delay = (punch_start_time - time.time()) if punch_start_time else None
        if delay > 0:
            logger.info(f"[PUNCH] Synchronizing: waiting {delay:.2f}s before hole punch...")
            await asyncio.sleep(delay)

        if punch_start_time:
            wait_time = punch_start_time - time.time()
            if wait_time > 0:
                logger.info(f"[PUNCH] Synchronizing: waiting {wait_time:.2f}s before hole punch...")
                await asyncio.sleep(wait_time)
        
        # Determine if hole punching is likely to work
        my_nat = self.nat_result.nat_type if self.nat_result else 'unknown'
        both_symmetric = my_nat == 'symmetric' and peer_nat_type == 'symmetric'
        
        # Attempt hole punching
        if not both_symmetric:
            logger.info(f"[PUNCH] Attempting hole punch | My NAT={my_nat}, Peer NAT={peer_nat_type}")
            punch_result = await self._attempt_hole_punch(target_peer_id, actual_addr, peer_nat_type)
            
            if punch_result.success:
                logger.info(f"[PUNCH] Hole punch SUCCESS in {punch_result.time_taken_ms:.0f}ms with {punch_result.attempts} attempts")
                self.metrics.record_hole_punch(
                    target_peer_id, True,
                    punch_result.time_taken_ms,
                    punch_result.attempts
                )
                
                # Establish QUIC over the punched hole
                # Use the address hole-punch actually confirmed, not stale signalling addr
                confirmed_addr = punch_result.peer_addr if punch_result.peer_addr else actual_addr
                return await self._establish_quic(target_peer_id, confirmed_addr)
        else:
            logger.warning(f"[PUNCH] Skipping hole punch: both peers have symmetric NAT (high failure probability)")
        
        # Hole punch failed or skipped, use relay
        logger.info("[PUNCH] Hole punch unsuccessful, falling back to relay mode")
        self.metrics.record_hole_punch(target_peer_id, False, 3000, 15)
        return await self._establish_relay(target_peer_id)
    
    async def _attempt_hole_punch(self, target_peer_id: str, peer_addr: Tuple[str, int],
                                   peer_nat_type: str) -> HolePunchResult:
        """Attempt UDP hole punching"""
        logger.info(f"Attempting hole punch to {peer_addr}")

        # A previous QUIC attempt may have closed the socket; re-create it for retries.
        await self._ensure_local_socket(preferred_port=self.local_port)
        
        my_nat = self.nat_result.nat_type if self.nat_result else 'unknown'
        puncher = BidirectionalHolePuncher(self.local_socket, self.peer_id)
        
        return await puncher.execute(peer_addr, my_nat, peer_nat_type)
    
    async def _establish_quic(self, target_peer_id: str, peer_addr: Tuple[str, int]) -> bool:
        """Establish QUIC connection after successful hole punch"""
        logger.info(f"[QUIC] Initiating QUIC handshake to {peer_addr[0]}:{peer_addr[1]}")
        
        try:
            # Close the hole punch socket - QUIC will create its own
            async with self._socket_lock:
                if self.local_socket:
                    self.local_socket.close()
                    self.local_socket = None
                    logger.debug(f"[SOCKET] Closed hole punch socket")
            
            ticket_store_file = f".session_tickets_{self.peer_id}.pkl"
            
            async with self._quic_lock:
                if self._quic_peer:
                    old_quic = self._quic_peer
                    self._quic_peer = None
                    await old_quic.close()

                self._quic_peer = QuicPeer(
                    self.peer_id,
                    self.cert_file,
                    self.key_file,
                    ticket_store_file=ticket_store_file
                )
            
            start_time = time.time()
            # Add timeout for QUIC connection - if peer isn't listening, fail quickly
            logger.debug(f"[QUIC] Connecting (timeout=5s)...")
            try:
                async with self._quic_lock:
                    self.protocol = await asyncio.wait_for(
                        self._quic_peer.connect(
                            peer_addr[0], peer_addr[1],
                            local_port=self.local_port  # Reuse hole-punched port
                        ),
                        timeout=5.0  # 5 second timeout for QUIC handshake
                    )
            except asyncio.TimeoutError:
                logger.warning(f"[QUIC] Handshake timeout after 5s to {peer_addr[0]}:{peer_addr[1]}")
                await asyncio.sleep(0.1)  # Brief pause before cleanup
                async with self._quic_lock:
                    quic = self._quic_peer
                    self._quic_peer = None
                if quic:
                    await quic.close()
                await self._ensure_local_socket(preferred_port=self.local_port)
                logger.info("[QUIC] Falling back to relay mode due to timeout")
                self.metrics.record_hole_punch(target_peer_id, True, 3000, 15)  # Mark as success but using relay
                return await self._establish_relay(target_peer_id)
            
            connect_time = (time.time() - start_time) * 1000
            is_0rtt = hasattr(self.protocol, '_quic') and self.protocol._quic.tls._session_resumed
            
            logger.info(f"[QUIC] Handshake complete in {connect_time:.1f}ms | 0-RTT={is_0rtt}")
            self.metrics.record_connection_established(target_peer_id, is_0rtt=is_0rtt)
            
            # Set up callbacks
            if self.on_chat_message:
                self.protocol.on_chat_message = self.on_chat_message
            if self.on_file_received:
                self.protocol.on_file_chunk = self.on_file_received
            
            # Start ping loop for RTT monitoring
            logger.debug(f"[METRICS] Starting RTT ping loop...")
            await self.metrics.start_ping_loop(target_peer_id, self.protocol, interval=5.0)
            
            # Notify server of success (with reconnect if needed)
            try:
                async with self._ws_lock:
                    if self._is_websocket_open():
                        await self.websocket.send(json.dumps({
                            'type': 'hole_punch_success',
                            'peer_id': self.peer_id,
                            'target_peer_id': target_peer_id
                        }))
                        logger.debug(f"[CONN] Notified server of successful P2P connection")
            except Exception as e:
                logger.warning(f"[CONN] Failed to notify server: {e}")
            
            if self.on_connected:
                self.on_connected(target_peer_id, False)  # Not relay
            
            logger.info(f"[CONN] Connected to {target_peer_id} (Direct P2P)")
            return True
        
        except Exception as e:
            logger.error(f"[QUIC] Connection failed: {e}")
            async with self._quic_lock:
                quic = self._quic_peer
                self._quic_peer = None
            if quic:
                await quic.close()
            await self._ensure_local_socket(preferred_port=self.local_port)
            return False
    
    async def _establish_relay(self, target_peer_id: str) -> bool:
        """Establish relay connection through server"""
        async with self._protocol_lock:
            if self.protocol is not None:
                logger.warning(f"[RELAY] Skipping relay setup - protocol already active")
                return False
        
        logger.info(f"[RELAY] Initiating WebSocket relay to {target_peer_id}")
        
        async with self._relay_lock:
            self.using_relay = True

        ws_url = f"ws://{self.server_host}:{self.server_ws_port}"
        
        self.relay_client = RelayClient(self.peer_id, ws_url)
        
        logger.debug(f"[RELAY] Connecting to relay server...")
        if not await self.relay_client.connect():
            logger.error("[RELAY] Failed to connect to relay server")
            return False
        logger.debug(f"[RELAY] Connected to relay server")
        
        logger.debug(f"[RELAY] Requesting relay session for {target_peer_id}...")
        if not await self.relay_client.request_relay(target_peer_id):
            logger.error("[RELAY] Failed to establish relay session")
            return False

        self.metrics.record_relay_fallback(target_peer_id, self.relay_client.session_id)
        logger.info(f"[RELAY] Session established | ID={self.relay_client.session_id}")
        
        # Create adapter for consistent interface
        adapter = RelayPeerAdapter(self.relay_client, target_peer_id)
        if self.on_chat_message:
            adapter.on_chat_message = self.on_chat_message
        
        self.protocol = adapter
        
        if self.on_connected:
            self.on_connected(target_peer_id, True)  # Using relay
        
        logger.info(f"[CONN] Connected to {target_peer_id} (Relay/WebSocket fallback)")
        return True
    
    async def listen_for_connections(self, callback=None):
        """Listen for incoming connection requests"""
        logger.info("\rListening for incoming connections...")
        print(f"\n\r[{self.peer_id}]> ", end='', flush=True)
        
        while True:
            try:
                # Check if reconnect needed (outside lock first)
                async with self._ws_lock:
                    if not self._is_websocket_open():
                        # Reconnect while holding lock
                        if not await self._reconnect_signalling_locked():
                            logger.error("Failed to reconnect, retrying...")
                            await asyncio.sleep(2.0)  # Back off before retry
                            continue
                    
                    if not self.websocket:
                        logger.warning("Websocket still None after reconnect attempt")
                        continue
                    
                message = await self.websocket.recv()
                
                # Message received and lock released
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'peer_info':
                    # Incoming connection request
                    peer_id = data['peer_id']
                    peer_addr = tuple(data['mapped_addr'])
                    peer_local_addr = tuple(data.get('local_addr', peer_addr))
                    
                    # Detect hairpin NAT
                    my_public_ip = self.nat_result.mapped_addr_1[0] if self.nat_result else None
                    peer_public_ip = peer_addr[0]
                    use_local_addr = (my_public_ip == peer_public_ip and peer_local_addr != peer_addr)
                    
                    if use_local_addr:
                        logger.info(f"Detected hairpin NAT (same public IP: {my_public_ip})")
                        logger.info(f"Using local address: {peer_local_addr} instead of {peer_addr}")
                        actual_addr = peer_local_addr
                    else:
                        actual_addr = peer_addr
                    
                    logger.info(f"Incoming connection from {peer_id} at {actual_addr}")
                    
                    # handle connection in seperate task so listener loop stays unblocked
                    asyncio.create_task(self._handle_incoming_connection(peer_id, actual_addr, data, callback))
                
                elif msg_type == 'relay_ready':
                    # Relay mode initiated by other peer
                    session_id = data.get('session_id')
                    initiator = data.get('initiator')
                    logger.info(f"Relay session {session_id} from {initiator}")
                    
                    # Set up relay receiver
                    async with self._relay_lock:
                        self.using_relay = True
                        if initiator:
                            self.relay_target_peer_id = initiator

                    if self.on_connected and initiator:
                        self.on_connected(initiator, True)

                elif msg_type == 'relay_frame':
                    self._handle_signalling_relay_frame(
                        data.get('source', ''),
                        data.get('payload', '')
                    )
            except websockets.exceptions.ConnectionClosed:
                await self._reconnect_signalling()
            except Exception as e:
                logger.error(f"Error in listen_for_connections: {e}")

    async def _handle_incoming_connection(self, peer_id: str, actual_addr: str, data: dict, callback=None):
        # Clear stale protocol/relay state from previous session
        async with self._protocol_lock:
            self.protocol = None
        async with self._relay_lock:
            self.using_relay = False

        # Start metrics
        self.metrics.start_connection(peer_id)
        
        # Wait for synchronized punch start time if provided
        punch_start_time = data.get('punch_start_time')
        delay = (punch_start_time - time.time()) if punch_start_time else None
        if delay and delay > 0:
            logger.info(f"Waiting {delay:.2f}s for synchronized hole punch start...")
            await asyncio.sleep(delay)
            
        if punch_start_time:
            wait_time = punch_start_time - time.time()
            if wait_time > 0:
                logger.info(f"Waiting {wait_time:.2f}s for synchronized hole punch start...")
                await asyncio.sleep(wait_time)
        
        # Attempt hole punch (peer will punch simultaneously)
        punch_result = await self._attempt_hole_punch(
            peer_id, actual_addr,
            data.get('nat_type', 'unknown')
        )
        
        if punch_result.success:
            self.metrics.record_hole_punch(peer_id, True, punch_result.time_taken_ms, punch_result.attempts)
            # Wait for QUIC connection as server
            # The initiating peer connects, we listen
            success = await self._listen_quic(peer_id)
            
            # If QUIC listen times out, fall back to relay
            if not success:
                logger.info("QUIC listen timed out, falling back to relay")
                success = await self._establish_relay(peer_id)
        else:
            self.metrics.record_hole_punch(peer_id, False, 3000, 15)
            success = await self._establish_relay(peer_id)
        
        if callback:
            callback(peer_id, success)

    async def _listen_quic(self, expected_peer_id: str) -> bool:
        """Listen for incoming QUIC connection"""
        logger.info(f"Listening for QUIC from {expected_peer_id} on port {self.local_port}")
        
        try:
            # Close the hole punch socket to free the port for QUIC
            async with self._socket_lock:
                if self.local_socket:
                    self.local_socket.close()
                    self.local_socket = None
                    logger.debug(f"Closed hole punch socket")
            
            async with self._quic_lock:
                if self._quic_peer:
                    old = self._quic_peer
                    self._quic_peer = None
                    await old.close()

                self._quic_peer = QuicPeer(
                    self.peer_id,
                    self.cert_file,
                    self.key_file
                )
            
            connected_event = asyncio.Event()
            
            def on_connection(protocol):
                self.protocol = protocol
                if self.on_chat_message:
                    protocol.on_chat_message = self.on_chat_message
                if self.on_file_received:
                    protocol.on_file_chunk = self.on_file_received
                connected_event.set()
            
            await self._quic_peer.listen('0.0.0.0', self.local_port, on_connection=on_connection)
            
            # If connection already arrived during listen() call itself, don't wait
            if not connected_event.is_set():
                try:
                    await asyncio.wait_for(connected_event.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    logger.error("Timeout waiting for QUIC connection")
                    async with self._quic_lock:
                        quic = self._quic_peer
                        self._quic_peer = None
                    if quic:
                        await quic.close()
                    self.local_port = 0
                    await self._ensure_local_socket(preferred_port=self.local_port)
                    return False
        
            logger.info("QUIC connection received")
            
            self.metrics.record_connection_established(expected_peer_id)
            await self.metrics.start_ping_loop(expected_peer_id, self.protocol, interval=5.0)
            
            if self.on_connected:
                self.on_connected(expected_peer_id, False)
            
            return True
        
        except Exception as e:
            logger.error(f"QUIC listen error: {e}")
            async with self._quic_lock:
                quic = self._quic_peer
                self._quic_peer = None
            if quic:
                await quic.close()
            self.local_port = 0
            await self._ensure_local_socket(preferred_port=self.local_port)
            return False
        
    
    async def send_chat(self, text: str):
        """Send chat message to connected peer"""
        async with self._relay_lock:
            if self.using_relay and self.relay_target_peer_id and not self.relay_client:
                msg = json.dumps({
                    'type': 'chat',
                    'from': self.peer_id,
                    'text': text,
                    'ts': time.time()
                }).encode()
                await self._send_relay_frame(self.relay_target_peer_id, msg)
                return

        async with self._protocol_lock:
            proto = self.protocol
            if proto and hasattr(proto, 'send_chat'):
                result = proto.send_chat(text, self.peer_id)
                if asyncio.iscoroutine(result):
                    await result
    
    async def send_file(self, filepath: str):
        """Send file to connected peer"""
        async with self._relay_lock:
            if self.using_relay:
                logger.warning("File transfer not available in relay mode")
                return

        async with self._protocol_lock:
            proto = self.protocol
            if proto and hasattr(proto, 'send_file'):
                file_id = str(uuid.uuid4())[:8]
                result = proto.send_file(filepath, file_id)
                if asyncio.iscoroutine(result):
                    await result

    def get_stats(self):
        """Get connection statistics"""
        proto = self.protocol
        if proto:
            return proto.get_stats()
        return {}
    
    async def stop(self):
        """Stop the peer node"""
        logger.info("[SHUTDOWN] Stopping peer node...")

        logger.debug("[SHUTDOWN] Closing QUIC connection...")
        async with self._quic_lock:
            quic = self._quic_peer
            self._quic_peer = None
        if quic:
            await quic.close()
            logger.debug("[SHUTDOWN] QUIC closed")
                
        logger.debug("[SHUTDOWN] Closing signalling websocket...")
        if self.websocket:
            await self.websocket.close()
            logger.debug("[SHUTDOWN] Websocket closed")
        
        logger.debug("[SHUTDOWN] Closing relay connection...")
        if self.relay_client:
            await self.relay_client.close()
            logger.debug("[SHUTDOWN] Relay closed")
        
        logger.debug("[SHUTDOWN] Closing UDP socket...")
        async with self._socket_lock:
            if self.local_socket:
                self.local_socket.close()
                logger.debug("[SHUTDOWN] UDP socket closed")
        
        logger.debug("[SHUTDOWN] Stopping metrics server...")
        self.metrics_server.stop()
        
        logger.info("[SHUTDOWN] Peer stopped")


async def interactive_mode(node: PeerNode, target_peer_id: str = None):
    """Interactive chat mode"""
    
    def on_chat(from_peer: str, text: str):
        print(f"\n[{from_peer}]: {text}")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)
    
    def on_connected(peer_id: str, is_relay: bool):
        mode = "relay" if is_relay else "direct"
        print(f"\n*** Connected to {peer_id} ({mode} mode) ***")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)

    def on_file_received(file_id: str, file_data: bytes, metadata: dict):
        filename = os.path.basename(metadata.get('filename', f"received_{file_id}.bin"))
        output_dir = Path("received_files") / node.peer_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / filename

        if output_path.exists():
            output_path = output_dir / f"{file_id}_{filename}"

        with open(output_path, 'wb') as f:
            f.write(file_data)

        print(f"\n*** File received: {filename} ({len(file_data)} bytes) -> {output_path} ***")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)
    
    node.on_chat_message = on_chat
    node.on_connected = on_connected
    node.on_file_received = on_file_received
    
    if target_peer_id:
        # Initiator mode - connect to peer with retries
        max_retries = 5
        retry_delay = 2.0  # seconds
        
        for attempt in range(1, max_retries + 1):
            print(f"Connecting to peer: {target_peer_id} (attempt {attempt}/{max_retries})...")
            success = await node.connect_to_peer(target_peer_id)
            if success:
                break
            
            if attempt < max_retries:
                print(f"Connection failed, retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
            else:
                print("Failed to connect after all retries")
                return
    else:
        # Listener mode - wait for connections
        print("\rWaiting for incoming connections...")
        asyncio.create_task(node.listen_for_connections())
    
    # Interactive chat loop
    print(f"\nType messages and press Enter. Commands: /stats, /file <path>, /quit")
    
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input(f"\r[{node.peer_id}]> "))
            
            if line.startswith('/quit'):
                break
            elif line.startswith('/stats'):
                stats = node.get_stats()
                print_formatted_stats(stats)
            elif line.startswith('/file '):
                filepath = line[6:].strip()
                if os.path.exists(filepath):
                    await node.send_file(filepath)
                else:
                    print(f"File not found: {filepath}")
            elif line:
                await node.send_chat(line)
        
        except EOFError:
            break
        except KeyboardInterrupt:
            break


def print_formatted_stats(stats: dict):
    """Print stats in a clean tabular format"""
    # Aggregate totals
    total_sent = 0
    total_received = 0
    total_msgs_sent = 0
    total_msgs_received = 0
    rtt_samples = []
    last_rtt = 0.0
    
    # Per-category stats
    categories = {
        'Control': {'sent': 0, 'recv': 0, 'msgs_sent': 0, 'msgs_recv': 0},
        'Chat': {'sent': 0, 'recv': 0, 'msgs_sent': 0, 'msgs_recv': 0},
        'File': {'sent': 0, 'recv': 0, 'msgs_sent': 0, 'msgs_recv': 0},
    }
    
    for stream_id, data in stats.items():
        stream_id = int(stream_id)
        cat_idx = (stream_id // 4) % 3
        cat_name = ['Control', 'Chat', 'File'][cat_idx]
        
        categories[cat_name]['sent'] += data.get('bytes_sent', 0)
        categories[cat_name]['recv'] += data.get('bytes_received', 0)
        categories[cat_name]['msgs_sent'] += data.get('messages_sent', 0)
        categories[cat_name]['msgs_recv'] += data.get('messages_received', 0)
        
        total_sent += data.get('bytes_sent', 0)
        total_received += data.get('bytes_received', 0)
        total_msgs_sent += data.get('messages_sent', 0)
        total_msgs_received += data.get('messages_received', 0)
        
        if data.get('last_rtt_ms', 0) > 0:
            last_rtt = data['last_rtt_ms']
        if data.get('avg_rtt_ms', 0) > 0:
            rtt_samples.append(data['avg_rtt_ms'])
    
    avg_rtt = sum(rtt_samples) / len(rtt_samples) if rtt_samples else 0
    
    # Format bytes nicely
    def fmt_bytes(b):
        if b >= 1024 * 1024:
            return f"{b / (1024*1024):.1f} MB"
        elif b >= 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b} B"
    
    # Print table
    print("\n" + "=" * 50)
    print("              CONNECTION STATISTICS")
    print("=" * 50)
    print(f"{'Category':<12} {'Sent':<12} {'Received':<12} {'Msgs ↑':<8} {'Msgs ↓':<8}")
    print("-" * 50)
    
    for cat, data in categories.items():
        if data['sent'] > 0 or data['recv'] > 0 or data['msgs_sent'] > 0 or data['msgs_recv'] > 0:
            print(f"{cat:<12} {fmt_bytes(data['sent']):<12} {fmt_bytes(data['recv']):<12} {data['msgs_sent']:<8} {data['msgs_recv']:<8}")
    
    print("-" * 50)
    print(f"{'TOTAL':<12} {fmt_bytes(total_sent):<12} {fmt_bytes(total_received):<12} {total_msgs_sent:<8} {total_msgs_received:<8}")
    print("=" * 50)
    print(f"  Last RTT: {last_rtt:.2f} ms    Avg RTT: {avg_rtt:.2f} ms")
    print("=" * 50 + "\n")


async def main():
    parser = argparse.ArgumentParser(description='NAT Traversal Peer')
    parser.add_argument('--peer-id', default=f'peer-{uuid.uuid4().hex[:6]}',
                        help='Unique peer identifier')
    parser.add_argument('--server', required=True, help='Rendezvous server address')
    parser.add_argument('--ws-port', type=int, default=8765, help='WebSocket port')
    parser.add_argument('--stun-port-1', type=int, default=3478, help='First STUN port')
    parser.add_argument('--stun-port-2', type=int, default=3479, help='Second STUN port')
    parser.add_argument('--metrics-port', type=int, default=9090, help='Metrics HTTP port')
    parser.add_argument('--connect', help='Target peer ID to connect to')
    parser.add_argument('--cert', help='TLS certificate file')
    parser.add_argument('--key', help='TLS private key file')
    
    args = parser.parse_args()
    
    print(f"=== NAT Traversal Peer ===")
    print(f"Peer ID: {args.peer_id}")
    print(f"Server: {args.server}:{args.ws_port}")
    print(f"Metrics: http://localhost:{args.metrics_port}/")
    print()
    
    node = PeerNode(
        peer_id=args.peer_id,
        server_host=args.server,
        server_ws_port=args.ws_port,
        server_stun_port_1=args.stun_port_1,
        server_stun_port_2=args.stun_port_2,
        cert_file=args.cert,
        key_file=args.key,
        metrics_port=args.metrics_port
    )
    
    try:
        await node.start()
        await interactive_mode(node, args.connect)
    finally:
        await node.stop()


if __name__ == '__main__':
    asyncio.run(main())
