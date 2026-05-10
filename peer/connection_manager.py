import asyncio
import json
import logging
import socket
import time
from typing import Optional, Tuple

from peer.hole_punch import BidirectionalHolePuncher, HolePunchResult
from peer.quic_peer import QuicPeer, QuicPeerProtocol
from peer.relay import RelayClient, RelayPeerAdapter

logger = logging.getLogger('connection_manager')


class ConnectionManager:
    
    def __init__(
        self,
        peer_id: str,
        server_host: str,
        server_ws_port: int,
        cert_file: str,
        key_file: str,
        metrics,            # MetricsCollector instance
        signaling_manager,  # SignalingManager instance
        stats_manager,      # StatManager instance
        protocol_lock: asyncio.Lock,  # shared lock from PeerNode
    ):
        # Identity & server config
        self.peer_id = peer_id
        self.server_host = server_host
        self.server_ws_port = server_ws_port
        self.cert_file = cert_file
        self.key_file = key_file

        # Shared service references
        self.metrics = metrics
        self.signaling_manager = signaling_manager
        self.stats_manager = stats_manager

        # Convenience shortcut kept in sync by PeerNode.start()
        self.websocket = None
        self.nat_result = None

        # UDP socket used for hole punching
        self.local_socket: Optional[socket.socket] = None
        self.local_port: int = 0

        # Active protocol (QUIC or relay adapter)
        self.protocol: Optional[QuicPeerProtocol] = None
        self._quic_peer: Optional[QuicPeer] = None  # kept alive to prevent GC

        # Relay state
        self.relay_client: Optional[RelayClient] = None
        self.using_relay: bool = False
        self.relay_target_peer_id: Optional[str] = None

        # Callbacks (set by PeerNode / CLI after construction)
        self.on_chat_message = None
        self.on_file_received = None
        self.on_connected = None

        # Locks (protocol_lock shared with PeerNode/StatManager; others owned here)
        self._ws_lock = asyncio.Lock()
        self._socket_lock = asyncio.Lock()
        self._quic_lock = asyncio.Lock()
        self._protocol_lock = protocol_lock  # shared reference
        self._relay_lock = asyncio.Lock()

    async def _ensure_local_socket(self, preferred_port: Optional[int] = None) -> None:
        """Ensure a valid UDP socket is bound, with TIME_WAIT retry on Windows."""
        async with self._socket_lock:
            if self.local_socket is not None:
                try:
                    self.local_socket.getsockname()
                    return  # still valid
                except OSError:
                    logger.warning("Existing local socket is no longer valid, recreating...")
                    self.local_socket.close()
                    self.local_socket = None
                    self.local_port = 0

            bind_port = preferred_port if preferred_port is not None else self.local_port

            if bind_port != 0:
                for attempt in range(5):
                    try:
                        self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        if hasattr(socket, 'SO_REUSEPORT'):
                            try:
                                self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                            except OSError:
                                pass
                        self.local_socket.bind(('0.0.0.0', bind_port))
                        self.local_socket.setblocking(False)
                        self.local_port = self.local_socket.getsockname()[1]
                        logger.info(f"Rebound local UDP socket on port: {self.local_port}")
                        return
                    except OSError as e:
                        self.local_socket.close()
                        self.local_socket = None
                        is_busy = "10013" in str(e) or "EADDRINUSE" in str(e)
                        if is_busy:
                            logger.warning(f"Port {bind_port} in use/TIME_WAIT (attempt {attempt+1}/5), retrying in 1s...")
                            await asyncio.sleep(1.0)
                        else:
                            logger.warning(f"Socket bind to port {bind_port} failed: {e}")
                            break
                logger.info(f"Preferred port {bind_port} unavailable after retries, using ephemeral")

            try:
                self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.local_socket.bind(('0.0.0.0', 0))
                self.local_socket.setblocking(False)
                self.local_port = self.local_socket.getsockname()[1]
                logger.info(f"Bound local UDP socket on ephemeral port: {self.local_port}")
            except OSError as e:
                if self.local_socket:
                    self.local_socket.close()
                    self.local_socket = None
                raise OSError(f"Failed to bind UDP socket (even ephemeral): {e}")

    async def _sync_stats_loop(self, target_peer_id: str):
        """Delegate to StatManager._sync_stats_loop (reads conn_manager.protocol directly)."""
        await self.stats_manager._sync_stats_loop(target_peer_id)

    async def _attempt_hole_punch(self, target_peer_id: str, peer_addr: Tuple[str, int],
                                   peer_nat_type: str) -> HolePunchResult:
        logger.info(f"Attempting hole punch to {peer_addr}")

        # A previous QUIC attempt may have closed the socket; re-create it for retries.
        await self._ensure_local_socket(preferred_port=self.local_port)
        
        my_nat = self.nat_result.nat_type if self.nat_result else 'unknown'
        puncher = BidirectionalHolePuncher(self.local_socket, self.peer_id)
        
        return await puncher.execute(peer_addr, my_nat, peer_nat_type, target_peer_id=target_peer_id)
    
    async def _establish_quic(self, target_peer_id: str, peer_addr: Tuple[str, int]) -> bool:
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
                            local_port=self.local_port,  # Reuse hole-punched port
                            target_peer_id=target_peer_id  # Pass peer ID for ticket keying
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
            is_0rtt = getattr(self.protocol, 'early_data_accepted', False)
            
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
            
            # Start periodic stats sync to metrics collector
            asyncio.create_task(self._sync_stats_loop(target_peer_id))
            
            # Notify server of success (with reconnect if needed)
            try:
                async with self._ws_lock:
                    if self.signaling_manager._is_websocket_open():
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
        self.metrics.record_connection_established(target_peer_id)
        
        # Start ping loop for RTT monitoring (same as QUIC mode)
        await self.metrics.start_ping_loop(target_peer_id, adapter, interval=5.0)
        
        # Start periodic stats sync to metrics collector
        asyncio.create_task(self._sync_stats_loop(target_peer_id))
        
        if self.on_connected:
            self.on_connected(target_peer_id, True)  # Using relay
        
        logger.info(f"[CONN] Connected to {target_peer_id} (Relay/WebSocket fallback)")
        return True
    
    async def _listen_quic(self, expected_peer_id: str) -> bool:
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

                ticket_store_file = f".session_tickets_{self.peer_id}.pkl"
                self._quic_peer = QuicPeer(
                    self.peer_id,
                    self.cert_file,
                    self.key_file,
                    ticket_store_file=ticket_store_file
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
            
            # Start periodic stats sync to metrics collector
            asyncio.create_task(self._sync_stats_loop(expected_peer_id))
            
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
    