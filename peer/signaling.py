import asyncio
import base64
import json
import logging
import socket
import websockets
from typing import Optional
from common.auth import ConnectionToken

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('signaling_manager')

class SignalingManager:
    
    def __init__(self, peer_id: str, server_host: str, server_ws_port: int):
        """
        Initialize SignalingManager
        
        Args:
            peer_id: This peer's ID
            server_host: Rendezvous server hostname/IP
            server_ws_port: Rendezvous server WebSocket port
        """
        # Connection info
        self.peer_id = peer_id
        self.server_host = server_host
        self.server_ws_port = server_ws_port
        
        # WebSocket connection
        self.websocket = None
        self._ws_lock = asyncio.Lock()
        
        # Peer state (will be updated after NAT classification)
        self.nat_result = None  # Will have .mapped_addr_1 and .nat_type
        self.local_port = 0      # Will be updated when socket is bound
        self._cached_local_ip = None  # Cached local/private IP address
    
    async def _ensure_signalling_connected(self) -> bool:
        if not self._is_websocket_open():
            return await self._reconnect_signalling_locked()
        return True

    async def _reconnect_signalling(self) -> bool:
        async with self._ws_lock:
            return await self._reconnect_signalling_locked()
        
    async def _reconnect_signalling_locked(self) -> bool:
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

    async def _register_with_server(self):
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

    async def _send_relay_frame(self, target_peer_id: str, payload: bytes) -> bool:
        """Send a relay frame via the signalling websocket (fallback path for listener peers)."""
        if len(payload) > 4096:
            logger.warning("Relay payload too large, dropping")
            return False

        payload_b64 = base64.b64encode(payload).decode()
        try:
            async with self._ws_lock:
                if not await self._ensure_signalling_connected():
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
    
    def _handle_signalling_relay_frame(
        self,
        source_peer: str,
        payload_b64: str,
        on_chat_message=None,
    ) -> None:
        """Handle relay frames received on the signalling websocket.

        Args:
            source_peer: Peer ID that sent the frame.
            payload_b64: Base64-encoded payload bytes.
            on_chat_message: Optional callback(from_peer, text) for chat messages.
        """
        try:
            payload = base64.b64decode(payload_b64)
            msg = json.loads(payload.decode())
            msg_type = msg.get('type')

            if msg_type == 'chat' and on_chat_message:
                on_chat_message(msg.get('from', source_peer), msg.get('text', ''))
            elif msg_type == 'control':
                control_type = msg.get('control_type')
                if control_type == 'ping':
                    asyncio.create_task(self._send_relay_frame(source_peer, json.dumps({
                        'type': 'control',
                        'control_type': 'pong',
                        'from': self.peer_id,
                        'seq': msg.get('seq'),
                        'ts': msg.get('ts')
                    }).encode()))
        except Exception as e:
            logger.error(f"Error handling signalling relay frame: {e}")

    async def _request_token_on_existing_ws(self, auth_client, target_peer_id: str) -> Optional[ConnectionToken]:
        """Request a connection token using the already-open signalling websocket.

        Args:
            auth_client: TokenAuthClient instance (owned by PeerNode).
            target_peer_id: The peer we want to connect to.
        """
        for attempt in range(2):
            try:
                async with self._ws_lock:
                    if not await self._ensure_signalling_connected():
                        return None

                    token = await auth_client.request_token_on_connection(
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

    def _get_local_ip(self) -> str:
        """Get the local/private IP address (LAN IP, not public). Result is cached."""
        if self._cached_local_ip is not None:
            return self._cached_local_ip
        
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
                                self._cached_local_ip = ip
                                return ip
            
            # Fallback: use socket method (may return public IP if no private IP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # Google DNS
            local_ip = s.getsockname()[0]
            s.close()
            self._cached_local_ip = local_ip
            return local_ip
        except Exception as e:
            logger.warning(f"Could not determine local IP: {e}")
            return None
    


    def _is_websocket_open(self) -> bool:
        if self.websocket is None:
            return False
        # A connection is open if it exists and hasn't been explicitly closed
        try:
            # Check if connection has a valid state by testing the object
            return hasattr(self.websocket, 'transport') and self.websocket.transport is not None
        except:
            return False

    async def stop(self):
        try:
            await self.websocket.close()
            logger.info("Closed signalling websocket")
        except Exception as e:
            logger.error(f"Failed to close signalling websocket: {e}")

