"""
Rendezvous Server
- STUN-style NAT probing (two UDP sockets on different ports)
- WebSocket signalling (exchange mapped addresses between peers)
- Token issuance (HMAC-SHA256 signed invite tokens with expiry)
"""

import asyncio
import json
import hmac
import hashlib
import base64
import time
import logging
import ssl
import os
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Tuple, Set
import websockets
from websockets.server import WebSocketServerProtocol

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('rendezvous')

# Configuration
STUN_PORT_1 = 3478
STUN_PORT_2 = 3479
WS_PORT = 8765
SECRET_KEY = os.environ.get('NAT_SECRET_KEY', 'default-secret-key-change-in-production').encode()
TOKEN_EXPIRY_SECONDS = 60


@dataclass
class PeerInfo:
    peer_id: str
    mapped_addr: Optional[Tuple[str, int]] = None
    local_addr: Optional[Tuple[str, int]] = None  # Private IP for hairpin NAT
    nat_type: Optional[str] = None
    websocket: Optional[WebSocketServerProtocol] = None
    waiting_for: Optional[str] = None  # peer_id this peer wants to connect to


class TokenManager:
    """HMAC-SHA256 token generation and verification"""
    
    @staticmethod
    def generate_token(peer_a_id: str, peer_b_id: str, expiry_timestamp: int) -> str:
        """Generate connection token"""
        message = f"{peer_a_id}:{peer_b_id}:{expiry_timestamp}".encode()
        signature = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
        token_data = {
            'peer_a': peer_a_id,
            'peer_b': peer_b_id,
            'expiry': expiry_timestamp,
            'sig': base64.b64encode(signature).decode()
        }
        return base64.b64encode(json.dumps(token_data).encode()).decode()
    
    @staticmethod
    def verify_token(token: str, peer_a_id: str, peer_b_id: str) -> Tuple[bool, str]:
        """Verify token validity and return (is_valid, error_message)"""
        try:
            token_data = json.loads(base64.b64decode(token))
            
            # Check peer IDs match
            if token_data['peer_a'] != peer_a_id or token_data['peer_b'] != peer_b_id:
                return False, "Token peer IDs don't match"
            
            # Check expiry
            if time.time() > token_data['expiry']:
                return False, "Token expired"
            
            # Verify signature
            message = f"{peer_a_id}:{peer_b_id}:{token_data['expiry']}".encode()
            expected_sig = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
            actual_sig = base64.b64decode(token_data['sig'])
            
            if not hmac.compare_digest(expected_sig, actual_sig):
                return False, "Invalid signature"
            
            return True, "OK"
        except Exception as e:
            return False, f"Token parse error: {e}"


class StunProtocol(asyncio.DatagramProtocol):
    """UDP protocol for STUN-style NAT probing"""
    
    def __init__(self, server: 'RendezvousServer', port_id: int):
        self.server = server
        self.port_id = port_id
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"STUN UDP socket {self.port_id} ready")
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming STUN probe and echo back mapped address"""
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            logger.debug(f"Ignoring non-UTF8 UDP packet from {addr}")
            return
        
        try:
            request = json.loads(text)
        except json.JSONDecodeError:
            logger.debug(f"Ignoring non-JSON UDP packet from {addr}: {text[:80]}")
            return
        
        if request.get('type') == 'probe':
            peer_id = request.get('peer_id', 'unknown')
            response = {
                'type': 'probe_response',
                'port_id': self.port_id,
                'mapped_ip': addr[0],
                'mapped_port': addr[1],
                'server_port': STUN_PORT_1 if self.port_id == 1 else STUN_PORT_2
            }
            self.transport.sendto(json.dumps(response).encode(), addr)
            logger.debug(f"Probe from {peer_id} @ {addr} on port {self.port_id}")
            
            # Store mapping for relay purposes
            self.server.peer_mappings[peer_id] = addr
    
    def error_received(self, exc):
        logger.error(f"STUN socket error: {exc}")


class RelayProtocol(asyncio.DatagramProtocol):
    """UDP relay for when hole punching fails"""
    
    def __init__(self, server: 'RendezvousServer'):
        self.server = server
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
        logger.info("Relay UDP socket ready")
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Relay UDP frames between peers"""
        try:
            # Frame format: 4-byte peer_id length + peer_id + payload
            if len(data) < 4:
                return
            
            id_len = int.from_bytes(data[:4], 'big')
            if len(data) < 4 + id_len:
                return
            
            target_peer_id = data[4:4+id_len].decode()
            payload = data[4+id_len:]
            
            # Size limit for relay mode (no large file transfers)
            if len(payload) > 4096:
                logger.warning(f"Relay payload too large ({len(payload)} bytes), dropping")
                return
            
            # Find target peer's address
            if target_peer_id in self.server.peer_mappings:
                target_addr = self.server.peer_mappings[target_peer_id]
                self.transport.sendto(payload, target_addr)
                logger.debug(f"Relayed {len(payload)} bytes to {target_peer_id}")
        except Exception as e:
            logger.error(f"Relay error: {e}")


class RendezvousServer:
    """Main rendezvous server coordinating peers"""
    
    def __init__(self, host: str = '0.0.0.0', ws_port: int = WS_PORT,
                 stun_port_1: int = STUN_PORT_1, stun_port_2: int = STUN_PORT_2):
        self.host = host
        self.ws_port = ws_port
        self.stun_port_1 = stun_port_1
        self.stun_port_2 = stun_port_2
        
        self.peers: Dict[str, PeerInfo] = {}
        self.peer_mappings: Dict[str, Tuple[str, int]] = {}  # peer_id -> (ip, port)
        self.active_sessions: Dict[str, Set[str]] = {}  # session_id -> {peer_ids}
        
        self.token_manager = TokenManager()
    
    async def handle_websocket(self, websocket: WebSocketServerProtocol):
        """Handle WebSocket connection from a peer"""
        peer_id = None
        try:
            async for message in websocket:
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'register':
                    peer_id = data['peer_id']
                    mapped_addr = tuple(data['mapped_addr']) if data.get('mapped_addr') else None
                    local_addr = tuple(data['local_addr']) if data.get('local_addr') else None
                    nat_type = data.get('nat_type')
                    
                    self.peers[peer_id] = PeerInfo(
                        peer_id=peer_id,
                        mapped_addr=mapped_addr,
                        local_addr=local_addr,
                        nat_type=nat_type,
                        websocket=websocket
                    )
                    
                    await websocket.send(json.dumps({
                        'type': 'registered',
                        'peer_id': peer_id,
                        'server_stun_ports': [self.stun_port_1, self.stun_port_2]
                    }))
                    logger.info(f"Peer {peer_id} registered, NAT type: {nat_type}, mapped: {mapped_addr}, local: {local_addr}")
                
                elif msg_type == 'request_token':
                    # Peer A requests token to connect to Peer B
                    peer_a_id = data['peer_a_id']
                    peer_b_id = data['peer_b_id']
                    expiry = int(time.time()) + TOKEN_EXPIRY_SECONDS
                    token = self.token_manager.generate_token(peer_a_id, peer_b_id, expiry)
                    
                    await websocket.send(json.dumps({
                        'type': 'token',
                        'token': token,
                        'expiry': expiry
                    }))
                    logger.info(f"Token issued for {peer_a_id} -> {peer_b_id}")
                
                elif msg_type == 'connect_request':
                    # Peer A wants to connect to Peer B
                    peer_a_id = data['peer_a_id']
                    peer_b_id = data['peer_b_id']
                    token = data['token']
                    
                    # Verify token
                    valid, error = self.token_manager.verify_token(token, peer_a_id, peer_b_id)
                    if not valid:
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': error
                        }))
                        continue
                    
                    # Check if peer B is registered
                    if peer_b_id not in self.peers:
                        online_peers = [p for p in self.peers.keys() if self.peers[p].websocket]
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': f'Target peer not registered. Online peers: {online_peers}'
                        }))
                        logger.debug(f"Connect request from {peer_a_id} to {peer_b_id} failed: peer not registered (online: {online_peers})")
                        continue
                    
                    peer_a = self.peers.get(peer_a_id)
                    peer_b = self.peers[peer_b_id]
                    
                    # Get peer addresses with fallback to local_addr
                    peer_a_addr = peer_a.mapped_addr if peer_a and peer_a.mapped_addr else (peer_a.local_addr if peer_a else None)
                    peer_b_addr = peer_b.mapped_addr if peer_b and peer_b.mapped_addr else (peer_b.local_addr if peer_b else None)
                    
                    if not peer_a_addr or not peer_b_addr:
                        logger.warning(f"Connect {peer_a_id} -> {peer_b_id}: Missing addresses: A={peer_a_addr}, B={peer_b_addr}")
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': f'Missing addresses: A has {peer_a_addr}, B has {peer_b_addr}'
                        }))
                        continue
                    
                    # Exchange addresses (use mapped_addr if available, fallback to local_addr)
                    if peer_a and peer_b:
                        # Calculate a synchronized start time (now + 500ms to allow message propagation)
                        punch_start_time = time.time() + 0.5
                        
                        # Notify both peers to start hole punching at the same time
                        await websocket.send(json.dumps({
                            'type': 'peer_info',
                            'peer_id': peer_b_id,
                            'mapped_addr': list(peer_b.mapped_addr) if peer_b.mapped_addr else list(peer_b.local_addr),
                            'local_addr': list(peer_b.local_addr) if peer_b.local_addr else list(peer_b.mapped_addr),
                            'nat_type': peer_b.nat_type,
                            'punch_start_time': punch_start_time
                        }))
                        
                        if peer_b.websocket:
                            await peer_b.websocket.send(json.dumps({
                                'type': 'peer_info',
                                'peer_id': peer_a_id,
                                'mapped_addr': list(peer_a.mapped_addr) if peer_a.mapped_addr else list(peer_a.local_addr),
                                'local_addr': list(peer_a.local_addr) if peer_a.local_addr else list(peer_a.mapped_addr),
                                'nat_type': peer_a.nat_type,
                                'token': token,  # B needs token to verify A
                                'punch_start_time': punch_start_time
                            }))
                        
                        logger.info(f"Exchanged addresses between {peer_a_id} and {peer_b_id}, punch starts at {punch_start_time}")
                
                elif msg_type == 'hole_punch_success':
                    # Peer reports successful hole punch
                    peer_a_id = data['peer_id']
                    peer_b_id = data['target_peer_id']
                    logger.info(f"Hole punch success: {peer_a_id} <-> {peer_b_id}")
                
                elif msg_type == 'relay_request':
                    # Peer requests relay mode (hole punch failed)
                    peer_a_id = data['peer_a_id']
                    peer_b_id = data['peer_b_id']
                    
                    # Enable relay for these peers
                    session_id = f"{min(peer_a_id, peer_b_id)}:{max(peer_a_id, peer_b_id)}"
                    self.active_sessions[session_id] = {peer_a_id, peer_b_id}
                    
                    await websocket.send(json.dumps({
                        'type': 'relay_ready',
                        'session_id': session_id
                    }))
                    
                    # Notify peer B
                    if peer_b_id in self.peers and self.peers[peer_b_id].websocket:
                        await self.peers[peer_b_id].websocket.send(json.dumps({
                            'type': 'relay_ready',
                            'session_id': session_id,
                            'initiator': peer_a_id
                        }))
                    
                    logger.info(f"Relay enabled for session {session_id}")
                
                elif msg_type == 'relay_frame':
                    # WebSocket-based relay frame
                    target_peer_id = data['target']
                    payload = base64.b64decode(data['payload'])
                    
                    if len(payload) > 4096:
                        logger.warning("Relay frame too large, dropping")
                        continue
                    
                    if target_peer_id in self.peers and self.peers[target_peer_id].websocket:
                        await self.peers[target_peer_id].websocket.send(json.dumps({
                            'type': 'relay_frame',
                            'source': peer_id,
                            'payload': data['payload']
                        }))
                
                elif msg_type == 'ping':
                    await websocket.send(json.dumps({'type': 'pong', 'ts': data.get('ts')}))
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Peer {peer_id} disconnected")
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            if peer_id and peer_id in self.peers:
                del self.peers[peer_id]
    
    async def start(self):
        """Start the rendezvous server"""
        loop = asyncio.get_event_loop()
        
        # Start STUN UDP sockets
        stun1_transport, _ = await loop.create_datagram_endpoint(
            lambda: StunProtocol(self, 1),
            local_addr=(self.host, self.stun_port_1)
        )
        stun2_transport, _ = await loop.create_datagram_endpoint(
            lambda: StunProtocol(self, 2),
            local_addr=(self.host, self.stun_port_2)
        )
        
        # Start WebSocket server
        ws_server = await websockets.serve(
            self.handle_websocket,
            self.host,
            self.ws_port
        )
        
        logger.info(f"Rendezvous server started:")
        logger.info(f"  STUN ports: {self.stun_port_1}, {self.stun_port_2}")
        logger.info(f"  WebSocket: ws://{self.host}:{self.ws_port}")
        
        try:
            await asyncio.Future()  # Run forever
        finally:
            stun1_transport.close()
            stun2_transport.close()
            ws_server.close()
            await ws_server.wait_closed()


async def main():
    import argparse
    parser = argparse.ArgumentParser(description='NAT Traversal Rendezvous Server')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--ws-port', type=int, default=WS_PORT, help='WebSocket port')
    parser.add_argument('--stun-port-1', type=int, default=STUN_PORT_1, help='First STUN port')
    parser.add_argument('--stun-port-2', type=int, default=STUN_PORT_2, help='Second STUN port')
    args = parser.parse_args()
    
    server = RendezvousServer(
        host=args.host,
        ws_port=args.ws_port,
        stun_port_1=args.stun_port_1,
        stun_port_2=args.stun_port_2
    )
    await server.start()


if __name__ == '__main__':
    asyncio.run(main())
