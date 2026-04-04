"""
Relay Fallback Client
When hole punching fails, peers connect via WebSocket relay through the rendezvous server.
Size-limited to chat/control only (no large file transfers).
"""

import asyncio
import json
import base64
import time
import logging
from dataclasses import dataclass
from typing import Optional, Callable, Dict
import websockets
from websockets.client import WebSocketClientProtocol

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('relay')

MAX_RELAY_PAYLOAD = 4096  # 4KB limit for relay mode


@dataclass
class RelayStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    frames_sent: int = 0
    frames_received: int = 0
    start_time: float = 0.0


class RelayClient:
    """
    WebSocket-based relay client for when direct P2P fails.
    Connects to rendezvous server and relays messages to peer.
    """
    
    def __init__(self, peer_id: str, server_url: str):
        """
        Args:
            peer_id: This peer's ID
            server_url: WebSocket URL of rendezvous server (ws://host:port)
        """
        self.peer_id = peer_id
        self.server_url = server_url
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.session_id: Optional[str] = None
        self.connected = asyncio.Event()
        self.stats = RelayStats()
        
        # Callbacks
        self.on_message: Optional[Callable[[str, bytes], None]] = None  # (from_peer, data)
        self.on_connected: Optional[Callable[[str], None]] = None  # (session_id)
        
        self._receive_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def connect(self) -> bool:
        """Connect to relay server"""
        try:
            self.websocket = await websockets.connect(self.server_url)
            
            # Register with server
            await self.websocket.send(json.dumps({
                'type': 'register',
                'peer_id': self.peer_id,
                'mapped_addr': None,  # Not needed for relay mode
                'nat_type': 'relay'
            }))
            
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get('type') == 'registered':
                logger.info(f"Registered with relay server as {self.peer_id}")
                self._running = True
                self._receive_task = asyncio.create_task(self._receive_loop())
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to connect to relay: {e}")
            return False
    
    async def request_relay(self, target_peer_id: str) -> bool:
        """
        Request relay mode with another peer.
        
        Args:
            target_peer_id: ID of peer to relay to
        """
        if not self.websocket:
            return False
        
        await self.websocket.send(json.dumps({
            'type': 'relay_request',
            'peer_a_id': self.peer_id,
            'peer_b_id': target_peer_id
        }))
        
        # Wait for relay_ready response (handled in receive loop)
        try:
            await asyncio.wait_for(self.connected.wait(), timeout=5.0)
            return True
        except asyncio.TimeoutError:
            logger.error("Relay request timeout")
            return False
    
    async def send(self, target_peer_id: str, data: bytes) -> bool:
        """
        Send data to peer through relay.
        
        Args:
            target_peer_id: Peer to send to
            data: Data to send (max 4KB)
        """
        if not self.websocket or not self._running:
            return False
        
        if len(data) > MAX_RELAY_PAYLOAD:
            logger.warning(f"Payload too large for relay ({len(data)} > {MAX_RELAY_PAYLOAD})")
            return False
        
        try:
            await self.websocket.send(json.dumps({
                'type': 'relay_frame',
                'target': target_peer_id,
                'payload': base64.b64encode(data).decode()
            }))
            
            self.stats.bytes_sent += len(data)
            self.stats.frames_sent += 1
            return True
        
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False
    
    async def send_chat(self, target_peer_id: str, text: str):
        """Send chat message through relay"""
        msg = json.dumps({
            'type': 'chat',
            'from': self.peer_id,
            'text': text,
            'ts': time.time()
        }).encode()
        return await self.send(target_peer_id, msg)
    
    async def send_control(self, target_peer_id: str, control_type: str, **kwargs):
        """Send control message through relay"""
        msg = json.dumps({
            'type': 'control',
            'control_type': control_type,
            'from': self.peer_id,
            **kwargs
        }).encode()
        return await self.send(target_peer_id, msg)
    
    async def _receive_loop(self):
        """Receive messages from relay server"""
        try:
            while self._running and self.websocket:
                message = await self.websocket.recv()
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'relay_ready':
                    self.session_id = data.get('session_id')
                    self.stats.start_time = time.time()
                    self.connected.set()
                    logger.info(f"Relay session established: {self.session_id}")
                    if self.on_connected:
                        self.on_connected(self.session_id)
                
                elif msg_type == 'relay_frame':
                    source_peer = data.get('source')
                    payload = base64.b64decode(data.get('payload', ''))
                    
                    self.stats.bytes_received += len(payload)
                    self.stats.frames_received += 1
                    
                    if self.on_message:
                        self.on_message(source_peer, payload)
                
                elif msg_type == 'pong':
                    pass  # Handled by ping logic
        
        except websockets.exceptions.ConnectionClosed:
            logger.info("Relay connection closed")
        except Exception as e:
            logger.error(f"Receive error: {e}")
        finally:
            self._running = False
            self.connected.clear()
    
    async def close(self):
        """Close relay connection"""
        self._running = False
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
        if self.websocket:
            await self.websocket.close()
    
    def get_stats(self) -> dict:
        """Get relay statistics"""
        uptime = time.time() - self.stats.start_time if self.stats.start_time else 0
        return {
            'session_id': self.session_id,
            'bytes_sent': self.stats.bytes_sent,
            'bytes_received': self.stats.bytes_received,
            'frames_sent': self.stats.frames_sent,
            'frames_received': self.stats.frames_received,
            'uptime_seconds': uptime,
            'is_relay': True
        }


class RelayPeerAdapter:
    """
    Adapts relay client to match QUIC peer interface for seamless fallback.
    Allows code to use same interface regardless of connection method.
    """
    
    def __init__(self, relay_client: RelayClient, target_peer_id: str):
        self.relay = relay_client
        self.target_peer_id = target_peer_id
        
        # Mimic QUIC protocol interface
        self.connected = relay_client.connected
        self.on_chat_message: Optional[Callable[[str, str], None]] = None
        
        # Set up message handler
        relay_client.on_message = self._handle_message
    
    def _handle_message(self, from_peer: str, data: bytes):
        """Handle incoming relay message"""
        try:
            msg = json.loads(data.decode())
            
            if msg.get('type') == 'chat' and self.on_chat_message:
                self.on_chat_message(msg.get('from', from_peer), msg.get('text', ''))
            
            elif msg.get('type') == 'control':
                control_type = msg.get('control_type')
                if control_type == 'ping':
                    # Send pong back
                    asyncio.create_task(self.relay.send_control(
                        from_peer, 'pong', seq=msg.get('seq')
                    ))
        
        except Exception as e:
            logger.error(f"Message handling error: {e}")
    
    def send_chat(self, text: str, from_peer: str):
        """Send chat message (matches QUIC interface)"""
        asyncio.create_task(self.relay.send_chat(self.target_peer_id, text))
    
    async def send_ping(self) -> Optional[float]:
        """Send ping (simplified for relay)"""
        # Relay mode doesn't support precise RTT measurement
        # Return estimated latency based on message round-trip
        return None
    
    def get_stats(self) -> Dict[int, dict]:
        """Get stats in QUIC-like format"""
        relay_stats = self.relay.get_stats()
        return {
            0: {  # Control stream
                'bytes_sent': 0,
                'bytes_received': 0,
                'last_rtt_ms': 0,
                'is_relay': True
            },
            4: {  # Chat stream
                'bytes_sent': relay_stats['bytes_sent'],
                'bytes_received': relay_stats['bytes_received'],
                'is_relay': True
            },
            8: {  # File stream (disabled in relay)
                'bytes_sent': 0,
                'bytes_received': 0,
                'disabled': True,
                'reason': 'File transfer disabled in relay mode'
            }
        }


async def main():
    """Test relay client"""
    import argparse
    parser = argparse.ArgumentParser(description='Relay Client Test')
    parser.add_argument('--peer-id', required=True)
    parser.add_argument('--server', default='ws://localhost:8765')
    parser.add_argument('--target', help='Target peer ID to relay to')
    args = parser.parse_args()
    
    client = RelayClient(args.peer_id, args.server)
    
    def on_message(from_peer: str, data: bytes):
        try:
            msg = json.loads(data.decode())
            print(f"[{from_peer}]: {msg}")
        except:
            print(f"[{from_peer}]: {data}")
    
    client.on_message = on_message
    
    if await client.connect():
        print(f"Connected as {args.peer_id}")
        
        if args.target:
            if await client.request_relay(args.target):
                print(f"Relay established with {args.target}")
                
                # Send test message
                await client.send_chat(args.target, "Hello via relay!")
                
                # Keep running
                await asyncio.sleep(60)
        else:
            print("Waiting for relay requests...")
            await asyncio.Future()
    
    await client.close()


if __name__ == '__main__':
    asyncio.run(main())
