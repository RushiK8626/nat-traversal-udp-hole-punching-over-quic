import asyncio
import argparse
import json
import base64
import logging
import os
import sys
import platform
import time
import socket
import uuid
import websockets
from pathlib import Path
from typing import Optional, Tuple
from peer.signaling import SignalingManager
from peer.stats import StatManager
from peer.connection_manager import ConnectionManager

# Add parent directory to path to allow imports when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from peer.nat_classifier import NATClassifier, NATClassificationResult
from peer.hole_punch import BidirectionalHolePuncher, HolePunchResult
from peer.quic_peer import QuicPeer, QuicPeerProtocol
from peer.relay import RelayClient, RelayPeerAdapter
from peer.metrics import MetricsCollector, MetricsServer
from peer.cli import run as run_cli
from common.auth import TokenAuthClient, ConnectionToken
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)
logger = logging.getLogger('main')


class PeerNode:

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

        # Components
        self.classifier = NATClassifier(
            server_host, server_stun_port_1, server_stun_port_2
        )
        self.metrics = MetricsCollector(peer_id)
        self.metrics_server = MetricsServer(self.metrics, port=metrics_port)
        self.auth_client = TokenAuthClient(peer_id, f"ws://{server_host}:{server_ws_port}")

        # Initialize SignalingManager (must come before cert gen so _get_local_ip() is available)
        self.signaling_manager = SignalingManager(peer_id, server_host, server_ws_port)

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
                san_ips=['127.0.0.1', self.signaling_manager._get_local_ip()],
                san_dns=['localhost']
            )

        # Locks for synchronizing access to shared resources
        self._ws_lock = asyncio.Lock()
        self._socket_lock = asyncio.Lock()
        self._quic_lock = asyncio.Lock()
        self._protocol_lock = asyncio.Lock()
        self._relay_lock = asyncio.Lock()

        # Initialize Stats Manager (shares _protocol_lock with PeerNode)
        self.stats_manager = StatManager(
            peer_id=peer_id,
            metrics=self.metrics,
            signaling_manager=self.signaling_manager,
            protocol_lock=self._protocol_lock,
        )

        # Initialize ConnectionManager (owns hole punch, QUIC, relay logic)
        self.conn_manager = ConnectionManager(
            peer_id=peer_id,
            server_host=server_host,
            server_ws_port=server_ws_port,
            cert_file=self.cert_file,
            key_file=self.key_file,
            metrics=self.metrics,
            signaling_manager=self.signaling_manager,
            stats_manager=self.stats_manager,
            protocol_lock=self._protocol_lock,
        )

        # Wire cross-references (breaks circular init dependency)
        self.stats_manager.conn_manager = self.conn_manager

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

        # Callbacks — private backing stores; use properties below to keep conn_manager in sync
        self._on_chat_message = None
        self._on_file_received = None
        self._on_connected = None

    # ── Callback properties ────────────────────────────────────────────────
    # Any assignment (e.g. node.on_chat_message = fn) is automatically
    # forwarded to conn_manager so the protocol gets wired correctly.

    @property
    def on_chat_message(self):
        return self._on_chat_message

    @on_chat_message.setter
    def on_chat_message(self, fn):
        self._on_chat_message = fn
        self.conn_manager.on_chat_message = fn

    @property
    def on_file_received(self):
        return self._on_file_received

    @on_file_received.setter
    def on_file_received(self, fn):
        self._on_file_received = fn
        self.conn_manager.on_file_received = fn

    @property
    def on_connected(self):
        return self._on_connected

    @on_connected.setter
    def on_connected(self, fn):
        self._on_connected = fn
        self.conn_manager.on_connected = fn


    async def start(self):
        """Start the peer node"""
        logger.info(f"[STARTUP] Initializing peer: {self.peer_id}")
        
        # Start metrics server
        logger.info(f"[STARTUP] Starting metrics HTTP server on port {self.metrics_port}...")
        self.metrics_server.start()
        
        logger.info(f"[STARTUP] Binding local UDP socket for NAT classification...")
        await self.conn_manager._ensure_local_socket(preferred_port=0)
        logger.info(f"[SOCKET] Bound to local port: {self.conn_manager.local_port}")
        
        # Classify NAT type
        logger.info(f"[NAT] Classifying NAT type via {self.server_host}:{self.server_stun_port_1}/{self.server_stun_port_2}...")
        self.nat_result = await self.classifier.classify_with_socket(
            self.peer_id, self.conn_manager.local_socket
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

        # Propagate connection state to SignalingManager and ConnectionManager
        self.signaling_manager.websocket = self.websocket
        self.signaling_manager.nat_result = self.nat_result
        self.signaling_manager.local_port = self.conn_manager.local_port
        self.conn_manager.websocket = self.websocket
        self.conn_manager.nat_result = self.nat_result

        await self.signaling_manager._register_with_server()
        
        local_ip = self.signaling_manager._get_local_ip() or 'N/A'
        nat_type = self.nat_result.nat_type if self.nat_result else 'unknown'
        nat_confidence = self.nat_result.confidence if self.nat_result else 'N/A'
        mapped_ip = f"{self.nat_result.mapped_addr_1[0]}:{self.nat_result.mapped_addr_1[1]}" if self.nat_result and self.nat_result.mapped_addr_1 else 'N/A'
        local_port = self.conn_manager.local_port

        local_addr   = f"{local_ip}:{local_port}"
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
        print(f"  UDP Socket : {local_port}")
        print(f"  NAT        : {nat_type} ({nat_confidence})")
        print(f"  Metrics    : {metrics_addr}/")
        print(f"  Ready to accept connections (peer-to-peer or relay)")
        print(f"{'=' * total_w}")
        print()

        return self

    async def connect_to_peer(self, target_peer_id: str) -> bool:
        """
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
        token = await self.signaling_manager._request_token_on_existing_ws(self.auth_client, target_peer_id)
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
                if not await self.signaling_manager._ensure_signalling_connected():
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
            await self.signaling_manager._reconnect_signalling()
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
            punch_result = await self.conn_manager._attempt_hole_punch(target_peer_id, actual_addr, peer_nat_type)
            
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
                return await self.conn_manager._establish_quic(target_peer_id, confirmed_addr)
        else:
            logger.warning(f"[PUNCH] Skipping hole punch: both peers have symmetric NAT (high failure probability)")
        
        # Hole punch failed or skipped, use relay
        logger.info("[PUNCH] Hole punch unsuccessful, falling back to relay mode")
        self.metrics.record_hole_punch(target_peer_id, False, 3000, 15)
        return await self.conn_manager._establish_relay(target_peer_id)
    
    async def listen_for_connections(self, callback=None):
        logger.info("\rListening for incoming connections...")
        print(f"\n\r[{self.peer_id}]> ", end='', flush=True)
        
        while True:
            try:
                # Check if reconnect needed
                async with self._ws_lock:
                    if not await self.signaling_manager._ensure_signalling_connected():
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
                    async with self.conn_manager._relay_lock:
                        self.conn_manager.using_relay = True
                        if initiator:
                            self.conn_manager.relay_target_peer_id = initiator

                    # Start metrics tracking for the listener-side relay
                    if initiator:
                        self.metrics.start_connection(initiator)
                        if self.nat_result:
                            self.metrics.record_nat_classification(
                                initiator,
                                self.nat_result.nat_type,
                                self.nat_result.confidence,
                                self.nat_result.mapped_addr_1
                            )
                        self.metrics.record_relay_fallback(initiator, session_id or '')
                        self.metrics.record_connection_established(initiator)
                        # Start RTT ping loop for listener-side relay
                        asyncio.create_task(self.stats_manager._relay_ping_loop(initiator))

                    if self.on_connected and initiator:
                        self.on_connected(initiator, True)

                elif msg_type == 'relay_frame':
                    self.signaling_manager._handle_signalling_relay_frame(
                        data.get('source', ''),
                        data.get('payload', '')
                    )
            except websockets.exceptions.ConnectionClosed:
                await self.signaling_manager._reconnect_signalling()
            except Exception as e:
                logger.error(f"Error in listen_for_connections: {e}")

    async def _handle_incoming_connection(self, peer_id: str, actual_addr: str, data: dict, callback=None):
        # Close previous QUIC server/connection to release the port
        async with self.conn_manager._quic_lock:
            old_quic = self.conn_manager._quic_peer
            self.conn_manager._quic_peer = None
        if old_quic:
            logger.info(f"[CLEANUP] Closing previous QUIC connection before new session with {peer_id}")
            await old_quic.close()
            # Brief pause for OS to release the socket
            await asyncio.sleep(0.2)

        # Clear stale protocol/relay state from previous session
        async with self._protocol_lock:
            self.conn_manager.protocol = None
        async with self.conn_manager._relay_lock:
            self.conn_manager.using_relay = False
            self.conn_manager.relay_target_peer_id = None
        if self.conn_manager.relay_client:
            try:
                await self.conn_manager.relay_client.close()
            except Exception:
                pass
            self.conn_manager.relay_client = None

        # Start metrics
        self.metrics.start_connection(peer_id)
        if self.nat_result:
            self.metrics.record_nat_classification(
                peer_id,
                self.nat_result.nat_type,
                self.nat_result.confidence,
                self.nat_result.mapped_addr_1
            )
        
        # Wait for synchronized punch start time if provided
        punch_start_time = data.get('punch_start_time')
        if punch_start_time:
            wait_time = punch_start_time - time.time()
            if wait_time > 0:
                logger.info(f"Waiting {wait_time:.2f}s for synchronized hole punch start...")
                await asyncio.sleep(wait_time)
        
        # Attempt hole punch (peer will punch simultaneously)
        punch_result = await self.conn_manager._attempt_hole_punch(
            peer_id, actual_addr,
            data.get('nat_type', 'unknown')
        )
        
        if punch_result.success:
            self.metrics.record_hole_punch(peer_id, True, punch_result.time_taken_ms, punch_result.attempts)
            # Wait for QUIC connection as server
            # The initiating peer connects, we listen
            success = await self.conn_manager._listen_quic(peer_id)

            # If QUIC listen times out, fall back to relay
            if not success:
                logger.info("QUIC listen timed out, falling back to relay")
                success = await self.conn_manager._establish_relay(peer_id)
        else:
            self.metrics.record_hole_punch(peer_id, False, 3000, 15)
            success = await self.conn_manager._establish_relay(peer_id)
        
        if callback:
            callback(peer_id, success)
    
    async def send_chat(self, text: str):
        """Send chat message to connected peer"""
        async with self.conn_manager._relay_lock:
            if self.conn_manager.using_relay and self.conn_manager.relay_target_peer_id and not self.conn_manager.relay_client:
                msg = json.dumps({
                    'type': 'chat',
                    'from': self.peer_id,
                    'text': text,
                    'ts': time.time()
                }).encode()
                success = await self.signaling_manager._send_relay_frame(self.conn_manager.relay_target_peer_id, msg)
                # Track send stats on the metrics collector for listener-side relay
                if success:
                    self.metrics.record_bytes(
                        self.conn_manager.relay_target_peer_id, stream_id=4, sent=len(msg), msgs_sent=1
                    )
                return

        async with self._protocol_lock:
            proto = self.conn_manager.protocol
            if proto and hasattr(proto, 'send_chat'):
                result = proto.send_chat(text, self.peer_id)
                if asyncio.iscoroutine(result):
                    await result
    
    async def send_file(self, filepath: str):
        """Send file to connected peer"""
        async with self.conn_manager._relay_lock:
            if self.conn_manager.using_relay:
                logger.warning("File transfer not available in relay mode")
                return

        async with self._protocol_lock:
            proto = self.conn_manager.protocol
            if proto and hasattr(proto, 'send_file'):
                file_id = str(uuid.uuid4())[:8]
                result = proto.send_file(filepath, file_id)
                if asyncio.iscoroutine(result):
                    await result

    def get_stats(self):
        """Get connection statistics (delegates to StatManager)."""
        return self.stats_manager.get_stats()

    async def stop(self):
        """Stop the peer node"""
        logger.info("[SHUTDOWN] Stopping peer node...")

        logger.debug("[SHUTDOWN] Closing QUIC connection...")
        async with self.conn_manager._quic_lock:
            quic = self.conn_manager._quic_peer
            self.conn_manager._quic_peer = None
        if quic:
            await quic.close()
            logger.debug("[SHUTDOWN] QUIC closed")
                
        logger.debug("[SHUTDOWN] Closing signalling websocket...")
        if self.websocket:
            await self.websocket.close()
            logger.debug("[SHUTDOWN] Websocket closed")
        
        logger.debug("[SHUTDOWN] Closing relay connection...")
        if self.conn_manager.relay_client:
            await self.conn_manager.relay_client.close()
            logger.debug("[SHUTDOWN] Relay closed")
        
        logger.debug("[SHUTDOWN] Closing UDP socket...")
        async with self.conn_manager._socket_lock:
            if self.conn_manager.local_socket:
                self.conn_manager.local_socket.close()
                logger.debug("[SHUTDOWN] UDP socket closed")
        
        logger.debug("[SHUTDOWN] Stopping metrics server...")
        self.metrics_server.stop()
        
        logger.info("[SHUTDOWN] Peer stopped")

        # Stop the signaling manager
        logger.info("[SHUTDOWN] Stopping signaling manager...")
        await self.signaling_manager.stop()

if __name__ == '__main__':
    # On Windows, use SelectorEventLoop to support add_reader() on raw sockets
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(run_cli())
