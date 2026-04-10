"""
Rendezvous Server
- STUN-style NAT probing (two UDP sockets on different ports)
- WebSocket signalling (exchange mapped addresses between peers)
- Signalling-only coordination (authentication is handled by QUIC TLS)
"""

import asyncio
import json
import base64
import time
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Set
import websockets

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('rendezvous')

# Configuration
STUN_PORT_1 = 3478
STUN_PORT_2 = 3479
WS_PORT = 8765


@dataclass
class PeerInfo:
    peer_id: str
    mapped_addr: Optional[Tuple[str, int]] = None
    local_addr: Optional[Tuple[str, int]] = None  # Private IP for hairpin NAT
    nat_type: Optional[str] = None
    websocket: Optional[Any] = None
    waiting_for: Optional[str] = None  # peer_id this peer wants to connect to


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
            if self.transport is None:
                return
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
                if self.transport is None:
                    return
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
    
    async def handle_websocket(self, websocket):
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

                    # Extract peer's public IP from WebSocket connection if NAT classification failed
                    if not mapped_addr and local_addr:
                        try:
                            # Get client's IP from websocket connection
                            client_ip = websocket.remote_address[0]
                            # Use the peer's local port as the likely mapped port
                            # (better than guessing - actual mapped port might differ, but this is our best guess)
                            mapped_port = local_addr[1]
                            mapped_addr = (client_ip, mapped_port)
                            logger.info(f"No mapped_addr from peer {peer_id}, using websocket source IP {client_ip}:{mapped_port} (derived from local port)")
                        except Exception as e:
                            logger.warning(f"Could not extract mapped address from websocket for {peer_id}: {e}")

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
                
                elif msg_type == 'connect_request':
                    # Peer A wants to connect to Peer B
                    peer_a_id = data.get('peer_a_id')
                    peer_b_id = data.get('peer_b_id')

                    if not peer_a_id or not peer_b_id:
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': 'connect_request missing peer_a_id or peer_b_id'
                        }))
                        continue

                    # Prevent identity spoofing inside signalling by requiring
                    # connect_request identity to match the registered websocket peer.
                    if peer_id != peer_a_id:
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': 'peer_a_id mismatch for websocket session'
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

                    # Always use mapped_addr (public) first, only use local_addr for hairpin NAT detection
                    # Never send private IP (10.x, 172.16-31.x, 192.168.x) as primary target
                    peer_a_addr = peer_a.mapped_addr if peer_a and peer_a.mapped_addr else None
                    peer_b_addr = peer_b.mapped_addr if peer_b else None
                    
                    if not peer_a_addr or not peer_b_addr:
                        logger.warning(f"Connect {peer_a_id} -> {peer_b_id}: Missing addresses: A={peer_a_addr}, B={peer_b_addr}")
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': f'Missing addresses: A has {peer_a_addr}, B has {peer_b_addr}'
                        }))
                        continue
                    
                    # Exchange addresses (always use mapped_addr for P2P attempts)
                    if peer_a and peer_b:
                        # Calculate a synchronized start time (now + 500ms to allow message propagation)
                        punch_start_time = time.time() + 0.5

                        # Notify both peers to start hole punching at the same time
                        # Send mapped_addr as primary target, local_addr for hairpin NAT detection
                        await websocket.send(json.dumps({
                            'type': 'peer_info',
                            'peer_id': peer_b_id,
                            'mapped_addr': list(peer_b.mapped_addr) if peer_b.mapped_addr else None,
                            'local_addr': list(peer_b.local_addr) if peer_b.local_addr else None,
                            'nat_type': peer_b.nat_type,
                            'punch_start_time': punch_start_time
                        }))

                        peer_b_ws = peer_b.websocket
                        if peer_b_ws is not None:
                            await peer_b_ws.send(json.dumps({
                                'type': 'peer_info',
                                'peer_id': peer_a_id,
                                'mapped_addr': list(peer_a.mapped_addr) if peer_a.mapped_addr else None,
                                'local_addr': list(peer_a.local_addr) if peer_a.local_addr else None,
                                'nat_type': peer_a.nat_type,
                                'punch_start_time': punch_start_time
                            }))

                        logger.info(f"Exchanged addresses between {peer_a_id} and {peer_b_id}, punch starts at {punch_start_time}")
                        logger.info(f"  {peer_a_id} -> {peer_b}: {peer_b.mapped_addr}")
                        logger.info(f"  {peer_b_id} -> {peer_a}: {peer_a.mapped_addr}")
                
                elif msg_type == 'hole_punch_success':
                    # Peer reports successful hole punch
                    peer_a_id = data['peer_id']
                    peer_b_id = data['target_peer_id']
                    logger.info(f"Hole punch success: {peer_a_id} <-> {peer_b_id}")
                
                elif msg_type == 'relay_request':
                    # Peer requests relay mode (hole punch failed)
                    peer_a_id = data.get('peer_a_id')
                    peer_b_id = data.get('peer_b_id')

                    if not peer_a_id or not peer_b_id:
                        await websocket.send(json.dumps({
                            'type': 'connect_failed',
                            'reason': 'relay_request missing peer_a_id or peer_b_id'
                        }))
                        continue
                    
                    # Enable relay for these peers
                    session_id = f"{min(peer_a_id, peer_b_id)}:{max(peer_a_id, peer_b_id)}"
                    self.active_sessions[session_id] = {peer_a_id, peer_b_id}
                    
                    await websocket.send(json.dumps({
                        'type': 'relay_ready',
                        'session_id': session_id
                    }))
                    
                    # Notify peer B
                    if peer_b_id in self.peers and self.peers[peer_b_id].websocket:
                        peer_b_ws = self.peers[peer_b_id].websocket
                        if peer_b_ws is not None:
                            await peer_b_ws.send(json.dumps({
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
                        target_ws = self.peers[target_peer_id].websocket
                        if target_ws is not None:
                            await target_ws.send(json.dumps({
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
