"""
NAT Traversal Peer - Main Orchestrator
Ties together all components:
- NAT classification
- Hole punching
- QUIC transport with 0-RTT
- Relay fallback
- Token authentication
- Metrics collection
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import time
import socket
import uuid
from pathlib import Path
from typing import Optional, Tuple

import websockets

from nat_classifier import NATClassifier, NATClassificationResult
from hole_punch import HolePuncher, BidirectionalHolePuncher, HolePunchResult
from quic_peer import QuicPeer, QuicPeerProtocol, generate_self_signed_cert
from relay import RelayClient, RelayPeerAdapter
from auth import TokenAuthClient, PeerAuthenticator, ConnectionToken
from metrics import MetricsCollector, MetricsServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
        
        # Certificate paths
        base_dir = Path(__file__).parent.parent / 'certs'
        self.cert_file = cert_file or str(base_dir / 'cert.pem')
        self.key_file = key_file or str(base_dir / 'key.pem')
        
        # Ensure certs exist
        if not os.path.exists(self.cert_file):
            logger.info("Generating self-signed certificate...")
            os.makedirs(base_dir, exist_ok=True)
            generate_self_signed_cert(self.cert_file, self.key_file)
        
        # Components
        self.classifier = NATClassifier(
            server_host, server_stun_port_1, server_stun_port_2
        )
        self.metrics = MetricsCollector(peer_id)
        self.metrics_server = MetricsServer(self.metrics, port=metrics_port)
        
        # State
        self.nat_result: Optional[NATClassificationResult] = None
        self.local_socket: Optional[socket.socket] = None
        self.local_port: int = 0
        self.websocket = None
        self.protocol: Optional[QuicPeerProtocol] = None
        self._quic_peer: Optional[QuicPeer] = None  # Keep alive to prevent GC
        self.relay_client: Optional[RelayClient] = None
        self.using_relay = False
        
        # Callbacks
        self.on_chat_message = None
        self.on_file_received = None
        self.on_connected = None
    
    async def start(self):
        """Start the peer node"""
        logger.info(f"Starting peer node: {self.peer_id}")
        
        # Start metrics server
        self.metrics_server.start()
        
        # Create local UDP socket for NAT probing and hole punching
        self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local_socket.bind(('0.0.0.0', 0))
        self.local_socket.setblocking(False)
        self.local_port = self.local_socket.getsockname()[1]
        logger.info(f"Bound to local port: {self.local_port}")
        
        # Classify NAT type
        self.nat_result = await self.classifier.classify_with_socket(
            self.peer_id, self.local_socket
        )
        
        if self.nat_result:
            logger.info(f"NAT Type: {self.nat_result.nat_type}")
            logger.info(f"Mapped Address: {self.nat_result.mapped_addr_1}")
        else:
            logger.warning("NAT classification failed, proceeding with unknown type")
        
        # Connect to rendezvous server
        ws_url = f"ws://{self.server_host}:{self.server_ws_port}"
        self.websocket = await websockets.connect(ws_url)
        
        # Register with server
        await self.websocket.send(json.dumps({
            'type': 'register',
            'peer_id': self.peer_id,
            'mapped_addr': list(self.nat_result.mapped_addr_1) if self.nat_result else None,
            'nat_type': self.nat_result.nat_type if self.nat_result else 'unknown'
        }))
        
        response = await self.websocket.recv()
        data = json.loads(response)
        logger.info(f"Registered with server: {data}")
        
        return self
    
    async def connect_to_peer(self, target_peer_id: str) -> bool:
        """
        Connect to another peer.
        
        Flow:
        1. Request token from server
        2. Send connect request with token
        3. Receive peer's mapped address
        4. Attempt hole punching
        5. If fails, fall back to relay
        6. Establish QUIC connection
        """
        logger.info(f"Connecting to peer: {target_peer_id}")
        
        # Start metrics tracking
        self.metrics.start_connection(target_peer_id)
        if self.nat_result:
            self.metrics.record_nat_classification(
                target_peer_id,
                self.nat_result.nat_type,
                self.nat_result.confidence,
                self.nat_result.mapped_addr_1
            )
        
        # Request connection token
        await self.websocket.send(json.dumps({
            'type': 'request_token',
            'peer_a_id': self.peer_id,
            'peer_b_id': target_peer_id
        }))
        
        response = await self.websocket.recv()
        token_data = json.loads(response)
        
        if token_data.get('type') != 'token':
            logger.error(f"Failed to get token: {token_data}")
            return False
        
        token = token_data['token']
        logger.info(f"Got connection token, expires in {token_data['expiry'] - int(time.time())}s")
        
        # Send connect request
        await self.websocket.send(json.dumps({
            'type': 'connect_request',
            'peer_a_id': self.peer_id,
            'peer_b_id': target_peer_id,
            'token': token
        }))
        
        # Wait for peer info
        response = await self.websocket.recv()
        peer_info = json.loads(response)
        
        if peer_info.get('type') == 'connect_failed':
            logger.error(f"Connection failed: {peer_info.get('reason')}")
            return False
        
        if peer_info.get('type') != 'peer_info':
            logger.error(f"Unexpected response: {peer_info}")
            return False
        
        peer_addr = tuple(peer_info['mapped_addr'])
        peer_nat_type = peer_info.get('nat_type', 'unknown')
        
        logger.info(f"Peer {target_peer_id} address: {peer_addr}, NAT: {peer_nat_type}")
        
        # Determine if hole punching is likely to work
        my_nat = self.nat_result.nat_type if self.nat_result else 'unknown'
        both_symmetric = my_nat == 'symmetric' and peer_nat_type == 'symmetric'
        
        # Attempt hole punching
        if not both_symmetric:
            punch_result = await self._attempt_hole_punch(target_peer_id, peer_addr, peer_nat_type)
            
            if punch_result.success:
                self.metrics.record_hole_punch(
                    target_peer_id, True,
                    punch_result.time_taken_ms,
                    punch_result.attempts
                )
                
                # Establish QUIC over the punched hole
                return await self._establish_quic(target_peer_id, peer_addr)
        else:
            logger.warning("Both peers have symmetric NAT, skipping hole punch")
        
        # Hole punch failed or skipped, use relay
        logger.info("Falling back to relay mode")
        self.metrics.record_hole_punch(target_peer_id, False, 3000, 15)
        return await self._establish_relay(target_peer_id)
    
    async def _attempt_hole_punch(self, target_peer_id: str, peer_addr: Tuple[str, int],
                                   peer_nat_type: str) -> HolePunchResult:
        """Attempt UDP hole punching"""
        logger.info(f"Attempting hole punch to {peer_addr}")
        
        my_nat = self.nat_result.nat_type if self.nat_result else 'unknown'
        puncher = BidirectionalHolePuncher(self.local_socket, self.peer_id)
        
        return await puncher.execute(peer_addr, my_nat, peer_nat_type)
    
    async def _establish_quic(self, target_peer_id: str, peer_addr: Tuple[str, int]) -> bool:
        """Establish QUIC connection after successful hole punch"""
        logger.info(f"Establishing QUIC connection to {peer_addr}")
        
        try:
            # Close the hole punch socket - QUIC will create its own
            if self.local_socket:
                self.local_socket.close()
                self.local_socket = None
                logger.debug(f"Closed hole punch socket for QUIC client")
            
            ticket_file = f".session_tickets_{self.peer_id}.pkl"
            self._quic_peer = QuicPeer(
                self.peer_id,
                self.cert_file,
                self.key_file,
                ticket_store_file=ticket_file
            )
            
            start_time = time.time()
            # Add timeout for QUIC connection - if peer isn't listening, fail quickly
            try:
                self.protocol = await asyncio.wait_for(
                    self._quic_peer.connect(
                        peer_addr[0], peer_addr[1],
                        local_port=self.local_port  # Reuse hole-punched port
                    ),
                    timeout=5.0  # 5 second timeout for QUIC handshake
                )
            except asyncio.TimeoutError:
                logger.warning(f"QUIC connection to {peer_addr} timed out after 5s")
                logger.info("Falling back to relay mode")
                self.metrics.record_hole_punch(target_peer_id, True, 3000, 15)  # Mark as success but using relay
                return await self._establish_relay(target_peer_id)
            
            connect_time = (time.time() - start_time) * 1000
            is_0rtt = hasattr(self.protocol, '_quic') and self.protocol._quic.tls._session_resumed
            
            self.metrics.record_connection_established(target_peer_id, is_0rtt=is_0rtt)
            
            logger.info(f"QUIC connected in {connect_time:.1f}ms (0-RTT: {is_0rtt})")
            
            # Set up callbacks
            if self.on_chat_message:
                self.protocol.on_chat_message = self.on_chat_message
            if self.on_file_received:
                self.protocol.on_file_chunk = self.on_file_received
            
            # Start ping loop for RTT monitoring
            await self.metrics.start_ping_loop(target_peer_id, self.protocol, interval=5.0)
            
            # Notify server of success
            await self.websocket.send(json.dumps({
                'type': 'hole_punch_success',
                'peer_id': self.peer_id,
                'target_peer_id': target_peer_id
            }))
            
            if self.on_connected:
                self.on_connected(target_peer_id, False)  # Not relay
            
            return True
        
        except Exception as e:
            logger.error(f"QUIC connection failed: {e}")
            return False
    
    async def _establish_relay(self, target_peer_id: str) -> bool:
        """Establish relay connection through server"""
        logger.info(f"Establishing relay connection for {target_peer_id}")
        
        self.using_relay = True
        ws_url = f"ws://{self.server_host}:{self.server_ws_port}"
        
        self.relay_client = RelayClient(self.peer_id, ws_url)
        
        if not await self.relay_client.connect():
            logger.error("Failed to connect to relay")
            return False
        
        if not await self.relay_client.request_relay(target_peer_id):
            logger.error("Failed to establish relay session")
            return False
        
        self.metrics.record_relay_fallback(target_peer_id, self.relay_client.session_id)
        
        # Create adapter for consistent interface
        adapter = RelayPeerAdapter(self.relay_client, target_peer_id)
        if self.on_chat_message:
            adapter.on_chat_message = self.on_chat_message
        
        self.protocol = adapter
        
        logger.info(f"Relay established, session: {self.relay_client.session_id}")
        
        if self.on_connected:
            self.on_connected(target_peer_id, True)  # Using relay
        
        return True
    
    async def listen_for_connections(self, callback=None):
        """Listen for incoming connection requests"""
        logger.info("Listening for incoming connections...")
        
        async for message in self.websocket:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'peer_info':
                # Incoming connection request
                peer_id = data['peer_id']
                peer_addr = tuple(data['mapped_addr'])
                token = data.get('token')
                
                logger.info(f"Incoming connection from {peer_id} at {peer_addr}")
                
                # Start metrics
                self.metrics.start_connection(peer_id)
                
                # Attempt hole punch (peer will punch simultaneously)
                punch_result = await self._attempt_hole_punch(
                    peer_id, peer_addr,
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
            
            elif msg_type == 'relay_ready':
                # Relay mode initiated by other peer
                session_id = data.get('session_id')
                initiator = data.get('initiator')
                logger.info(f"Relay session {session_id} from {initiator}")
                
                self.using_relay = True
                # Set up relay receiver
    
    async def _listen_quic(self, expected_peer_id: str) -> bool:
        """Listen for incoming QUIC connection"""
        logger.info(f"Listening for QUIC from {expected_peer_id} on port {self.local_port}")
        
        try:
            # Close the hole punch socket to free the port for QUIC
            if self.local_socket:
                self.local_socket.close()
                self.local_socket = None
                logger.debug(f"Closed hole punch socket")
            
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
                connected_event.set()
            
            await self._quic_peer.listen('0.0.0.0', self.local_port, on_connection=on_connection)
            
            # Wait for connection with timeout
            try:
                await asyncio.wait_for(connected_event.wait(), timeout=10.0)
                logger.info("QUIC connection received")
                
                self.metrics.record_connection_established(expected_peer_id)
                await self.metrics.start_ping_loop(expected_peer_id, self.protocol, interval=5.0)
                
                return True
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for QUIC connection")
                return False
        
        except Exception as e:
            logger.error(f"QUIC listen error: {e}")
            return False
    
    def send_chat(self, text: str):
        """Send chat message to connected peer"""
        if self.protocol:
            self.protocol.send_chat(text, self.peer_id)
    
    async def send_file(self, filepath: str):
        """Send file to connected peer"""
        if self.using_relay:
            logger.warning("File transfer not available in relay mode")
            return
        
        if self.protocol and hasattr(self.protocol, 'send_file'):
            file_id = str(uuid.uuid4())[:8]
            await self.protocol.send_file(filepath, file_id)
    
    def get_stats(self):
        """Get connection statistics"""
        if self.protocol:
            return self.protocol.get_stats()
        return {}
    
    async def stop(self):
        """Stop the peer node"""
        logger.info("Stopping peer node...")
        
        if self.websocket:
            await self.websocket.close()
        
        if self.relay_client:
            await self.relay_client.close()
        
        if self.local_socket:
            self.local_socket.close()
        
        self.metrics_server.stop()


async def interactive_mode(node: PeerNode, target_peer_id: str = None):
    """Interactive chat mode"""
    
    def on_chat(from_peer: str, text: str):
        print(f"\n[{from_peer}]: {text}")
        print(f"[{node.peer_id}]> ", end='', flush=True)
    
    def on_connected(peer_id: str, is_relay: bool):
        mode = "relay" if is_relay else "direct"
        print(f"\n*** Connected to {peer_id} ({mode} mode) ***")
        print(f"[{node.peer_id}]> ", end='', flush=True)
    
    node.on_chat_message = on_chat
    node.on_connected = on_connected
    
    if target_peer_id:
        # Initiator mode - connect to peer
        success = await node.connect_to_peer(target_peer_id)
        if not success:
            print("Failed to connect")
            return
    else:
        # Listener mode - wait for connections
        print("Waiting for incoming connections...")
        asyncio.create_task(node.listen_for_connections())
    
    # Interactive chat loop
    print(f"\nType messages and press Enter. Commands: /stats, /file <path>, /quit")
    
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input(f"[{node.peer_id}]> "))
            
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
                node.send_chat(line)
        
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
