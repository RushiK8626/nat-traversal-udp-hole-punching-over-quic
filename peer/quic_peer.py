"""
QUIC Peer using aioquic
- Self-signed TLS cert for QUIC handshake
- Three streams: 0=control/ping, 1=chat/data, 2=file transfer  
- Session ticket caching for 0-RTT resumption
- Binds to same UDP socket used for hole punching
"""

import asyncio
import json
import time
import os
import logging
import ssl
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, Any, Tuple
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    QuicEvent, StreamDataReceived, ConnectionTerminated,
    HandshakeCompleted, ConnectionIdIssued
)
from aioquic.tls import SessionTicket, SessionTicketHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('quic_peer')

# Stream IDs - Client uses 0,4,8 (% 4 == 0), Server uses 1,5,9 (% 4 == 1)
# We'll dynamically pick based on whether we're client or server
STREAM_CONTROL_CLIENT = 0
STREAM_CHAT_CLIENT = 4
STREAM_FILE_CLIENT = 8

STREAM_CONTROL_SERVER = 1
STREAM_CHAT_SERVER = 5
STREAM_FILE_SERVER = 9

# Message types for control stream
MSG_PING = 'ping'
MSG_PONG = 'pong'
MSG_CHAT = 'chat'
MSG_FILE_START = 'file_start'
MSG_FILE_CHUNK = 'file_chunk'
MSG_FILE_END = 'file_end'


@dataclass
class StreamStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    last_rtt_ms: float = 0.0
    rtt_samples: list = field(default_factory=list)


@dataclass
class TicketEntry:
    """Wrapper for session ticket with metadata"""
    ticket: SessionTicket
    peer_addr: Tuple[str, int]  # (host, port)
    created_time: float
    
    def is_expired(self) -> bool:
        """Check if ticket is expired"""
        # Check aioquic ticket expiry
        if hasattr(self.ticket, 'is_expired') and callable(self.ticket.is_expired):
            return self.ticket.is_expired()
        
        # Fallback: check if ticket has expiry_time attribute
        if hasattr(self.ticket, 'expiry_time'):
            return time.time() > self.ticket.expiry_time
        
        # Fallback: check age (assume 1 hour expiry)
        return (time.time() - self.created_time) > 3600


class SessionTicketStore:
    """Stores session tickets for 0-RTT resumption with peer tracking"""
    
    def __init__(self, ticket_file: Optional[str] = None):
        self.ticket_entries: Dict[Tuple[str, int], TicketEntry] = {}  # {(host, port): TicketEntry}
        self.ticket_file = ticket_file
        if self.ticket_file:
            logger.info(f"Initializing ticket store with file: {os.path.abspath(self.ticket_file)}")
        if ticket_file and os.path.exists(ticket_file):
            self._load_tickets()
        else:
            if ticket_file:
                logger.debug(f"Ticket file does not exist yet: {ticket_file}")
    
    def add(self, ticket: SessionTicket) -> None:
        """
        Store a session ticket.
        
        Note: Called as callback from aioquic during handshake.
        We store with a placeholder address - tickets are retrieved by calling
        add_for_peer() after successful connection to associate with actual peer.
        """
        if ticket is None:
            logger.debug("Received None ticket")
            return
        
        try:
            # Store with placeholder - will be overwritten when associated with peer
            entry = TicketEntry(ticket=ticket, peer_addr=("unknown", 0), created_time=time.time())
            # Use tuple of peer_addr as key (even though it's "unknown", won't collide)
            key = ("unknown", 0)
            
            self.ticket_entries[key] = entry
            logger.info(f"Session ticket received from server | Expiry={self._get_expiry_str(entry)} | Stored temporarily")
            
            if self.ticket_file:
                self._save_tickets()
        except Exception as e:
            logger.error(f"Failed to add ticket: {e}")

    def add_for_peer(self, ticket: SessionTicket, peer_addr: Tuple[str, int]) -> None:
        """
        Store a session ticket associated with a specific peer.
        Call this AFTER successful connection to associate ticket with peer.
        """
        if ticket is None or not peer_addr:
            return
        
        try:
            entry = TicketEntry(ticket=ticket, peer_addr=peer_addr, created_time=time.time())
            self.ticket_entries[peer_addr] = entry
            
            logger.info(f"Session ticket associated with {peer_addr[0]}:{peer_addr[1]} | Total: {len(self.ticket_entries)}")
            
            if self.ticket_file:
                self._save_tickets()
        except Exception as e:
            logger.error(f"Failed to add ticket for peer: {e}")
    
    def get_ticket_for_peer(self, peer_addr: Tuple[str, int]) -> Optional[SessionTicket]:
        """
        Retrieve a valid (non-expired) session ticket for a specific peer.
        Returns the ticket if found and valid, None otherwise.
        """
        if peer_addr not in self.ticket_entries:
            logger.debug(f"No ticket found for {peer_addr[0]}:{peer_addr[1]}")
            return None
        
        entry = self.ticket_entries[peer_addr]
        
        if entry.is_expired():
            logger.info(f"Ticket for {peer_addr[0]}:{peer_addr[1]} is expired, removing")
            del self.ticket_entries[peer_addr]
            if self.ticket_file:
                self._save_tickets()
            return None
        
        logger.info(f"Using stored session ticket for 0-RTT with {peer_addr[0]}:{peer_addr[1]}")
        return entry.ticket
    
    def pop(self, peer_addr: Tuple[str, int]) -> Optional[SessionTicket]:
        """
        Retrieve and remove a session ticket for a peer.
        Use after consuming ticket for 0-RTT.
        """
        if peer_addr not in self.ticket_entries:
            return None
        
        entry = self.ticket_entries.pop(peer_addr)
        logger.info(f"Removed ticket for {peer_addr[0]}:{peer_addr[1]} after 0-RTT use")
        
        if self.ticket_file:
            self._save_tickets()
        
        return entry.ticket
    
    def _save_tickets(self):
        """Persist tickets to file using pickle"""
        try:
            import pickle
            with open(self.ticket_file, 'wb') as f:
                pickle.dump(self.ticket_entries, f)
            logger.debug(f"Saved {len(self.ticket_entries)} tickets to {self.ticket_file}")
        except Exception as e:
            logger.error(f"Failed to save tickets: {e}")
    
    def _load_tickets(self):
        """Load tickets from file using pickle"""
        try:
            import pickle
            with open(self.ticket_file, 'rb') as f:
                loaded_entries = pickle.load(f)
                self.ticket_entries = loaded_entries
            logger.info(f"✓ Loaded {len(self.ticket_entries)} session tickets from {os.path.abspath(self.ticket_file)}")
            for peer_addr, entry in self.ticket_entries.items():
                logger.info(f"  - Peer {peer_addr[0]}:{peer_addr[1]} | Expires: {self._get_expiry_str(entry)}")
        except Exception as e:
            logger.warning(f"Failed to load tickets: {e}")
            self.ticket_entries = {}

    def _get_expiry_str(self, entry: TicketEntry) -> str:
        """Get human-readable expiry time"""
        if hasattr(entry.ticket, 'expiry_time'):
            remaining = entry.ticket.expiry_time - time.time()
            if remaining > 0:
                return f"{remaining:.0f}s remaining"
        return "unknown"
    
    def cleanup_expired(self) -> int:
        """Remove all expired tickets. Returns count of removed tickets."""
        expired_peers = [
            addr for addr, entry in self.ticket_entries.items()
            if entry.is_expired()
        ]
        
        for addr in expired_peers:
            del self.ticket_entries[addr]
        
        if expired_peers:
            logger.info(f"Cleaned up {len(expired_peers)} expired tickets")
            if self.ticket_file:
                self._save_tickets()
        
        return len(expired_peers)
    
class QuicPeerProtocol(QuicConnectionProtocol):
    """Custom QUIC protocol handling multiple streams"""
    
    def __init__(self, *args, is_client: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.peer_id: Optional[str] = None
        self.is_client = is_client
        self.connected = asyncio.Event()
        self.early_data_accepted = False
        
        # Select stream IDs based on client/server role
        if is_client:
            self.stream_control = STREAM_CONTROL_CLIENT
            self.stream_chat = STREAM_CHAT_CLIENT
            self.stream_file = STREAM_FILE_CLIENT
        else:
            self.stream_control = STREAM_CONTROL_SERVER
            self.stream_chat = STREAM_CHAT_SERVER
            self.stream_file = STREAM_FILE_SERVER
        
        self.stream_stats: Dict[int, StreamStats] = {
            0: StreamStats(),  # Control streams
            1: StreamStats(),
            4: StreamStats(),  # Chat streams
            5: StreamStats(),
            8: StreamStats(),  # File streams
            9: StreamStats()
        }
        
        # Callbacks
        self.on_chat_message: Optional[Callable[[str, str], None]] = None
        self.on_file_chunk: Optional[Callable[[str, bytes, dict], None]] = None
        self.on_ping: Optional[Callable[[float], None]] = None
        
        # Ping tracking
        self._ping_times: Dict[int, float] = {}
        self._ping_seq = 0
        
        # File transfer state
        self._file_transfers: Dict[str, dict] = {}
        self._file_stream_buffer: bytes = b''  # Buffer for framed file data
    
    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events"""
        if isinstance(event, HandshakeCompleted):
            self.early_data_accepted = getattr(event, 'early_data_accepted', False)
            logger.info(f"[QUIC-HS] Handshake completed | 0-RTT={'YES' if self.early_data_accepted else 'NO'} | Client={self.is_client}")
            self.connected.set()
        
        elif isinstance(event, StreamDataReceived):
            self._handle_stream_data(event.stream_id, event.data, event.end_stream)
        
        elif isinstance(event, ConnectionTerminated):
            logger.warning(f"[QUIC-TERM] Connection terminated | Error={event.error_code} | Reason={event.reason_phrase}")
    
    def _handle_stream_data(self, stream_id: int, data: bytes, end_stream: bool):
        """Handle data received on a stream"""
        import struct
        
        # Determine stream type: control (0,1), chat (4,5), file (8,9)
        stream_type = stream_id % 4  # 0 = client bidir, 1 = server bidir
        stream_category = (stream_id // 4) % 3  # 0 = control, 1 = chat, 2 = file
        
        if stream_id not in self.stream_stats:
            self.stream_stats[stream_id] = StreamStats()
        
        self.stream_stats[stream_id].bytes_received += len(data)
        
        try:
            # Control stream (0 or 1) and Chat stream (4 or 5) - use length-prefix framing
            if stream_category == 0 or stream_category == 1:
                # Store buffered data per stream
                if not hasattr(self, '_stream_buffers'):
                    self._stream_buffers = {}
                if stream_id not in self._stream_buffers:
                    self._stream_buffers[stream_id] = b''
                
                self._stream_buffers[stream_id] += data
                
                # Process complete framed messages
                while len(self._stream_buffers[stream_id]) >= 4:
                    msg_len = struct.unpack('>I', self._stream_buffers[stream_id][:4])[0]
                    if len(self._stream_buffers[stream_id]) < 4 + msg_len:
                        break  # Wait for complete message
                    
                    msg_data = self._stream_buffers[stream_id][4:4 + msg_len]
                    self._stream_buffers[stream_id] = self._stream_buffers[stream_id][4 + msg_len:]
                    
                    self.stream_stats[stream_id].messages_received += 1
                    
                    msg = json.loads(msg_data.decode())
                    
                    # Control stream
                    if stream_category == 0:
                        self._handle_control_message(msg, stream_id)
                    # Chat stream
                    else:
                        if msg.get('type') == MSG_CHAT and self.on_chat_message:
                            self.on_chat_message(msg.get('from', 'unknown'), msg.get('text', ''))
            
            # File stream (8 or 9) - has its own error handling for binary chunks
            elif stream_category == 2:
                self._handle_file_data(data)
        
        except Exception as e:
            # Don't log errors for file stream - binary chunks will fail JSON decode
            if stream_category != 2:
                logger.error(f"Error handling stream {stream_id} data: {e}")
    
    def _handle_control_message(self, msg: dict, received_stream_id: int = 0):
        """Handle control stream messages"""
        import struct
        
        msg_type = msg.get('type')
        
        if msg_type == MSG_PING:
            # Respond with pong on OUR control stream (not the received one)
            pong = json.dumps({
                'type': MSG_PONG,
                'seq': msg.get('seq'),
                'ts': msg.get('ts'),
                'rtt_ms': (time.time() - msg.get('ts', time.time())) * 1000
            }).encode()
            # Frame with length prefix
            framed_pong = struct.pack('>I', len(pong)) + pong
            self._quic.send_stream_data(self.stream_control, framed_pong, end_stream=False)
            self.transmit()
        
        elif msg_type == MSG_PONG:
            seq = msg.get('seq')
            if seq in self._ping_times:
                rtt_ms = (time.time() - self._ping_times[seq]) * 1000
                self.stream_stats[self.stream_control].last_rtt_ms = rtt_ms
                self.stream_stats[self.stream_control].rtt_samples.append(rtt_ms)
                del self._ping_times[seq]
                logger.debug(f"RTT: {rtt_ms:.1f}ms")
                if self.on_ping:
                    self.on_ping(rtt_ms)
    
    def _handle_file_data(self, data: bytes):
        """Handle file transfer data with length-prefix framing"""
        import struct
        
        # Add incoming data to buffer
        self._file_stream_buffer += data
        
        # Process complete frames from buffer
        while len(self._file_stream_buffer) >= 4:
            # Read length prefix
            msg_len = struct.unpack('>I', self._file_stream_buffer[:4])[0]
            
            # Check if we have the complete message
            if len(self._file_stream_buffer) < 4 + msg_len:
                break  # Wait for more data
            
            # Extract the message
            msg_data = self._file_stream_buffer[4:4 + msg_len]
            self._file_stream_buffer = self._file_stream_buffer[4 + msg_len:]
            
            # Process the message
            self._process_file_message(msg_data)
    
    def _process_file_message(self, data: bytes):
        """Process a single file transfer message"""
        # Try to parse as JSON metadata
        try:
            msg = json.loads(data.decode('utf-8'))
            msg_type = msg.get('type')
            
            if msg_type == MSG_FILE_START:
                file_id = msg.get('file_id')
                self._file_transfers[file_id] = {
                    'filename': msg.get('filename'),
                    'size': msg.get('size'),
                    'chunks': []
                }
                logger.info(f"File transfer started: {msg.get('filename')}")
                return
            
            elif msg_type == MSG_FILE_END:
                file_id = msg.get('file_id')
                if file_id in self._file_transfers:
                    transfer = self._file_transfers[file_id]
                    logger.info(f"File transfer complete: {transfer['filename']}")
                    if self.on_file_chunk:
                        self.on_file_chunk(file_id, b''.join(transfer['chunks']), transfer)
                    del self._file_transfers[file_id]
                return
        
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Not JSON, treat as binary chunk
        
        # Raw binary chunk - add to active transfer
        for file_id, transfer in self._file_transfers.items():
            transfer['chunks'].append(data)
            break
    
    async def send_ping(self) -> Optional[float]:
        """Send ping and wait for pong, return RTT in ms"""
        import struct
        
        self._ping_seq += 1
        seq = self._ping_seq
        self._ping_times[seq] = time.time()
        
        ping = json.dumps({
            'type': MSG_PING,
            'seq': seq,
            'ts': time.time()
        }).encode()
        
        # Frame with length prefix
        framed_ping = struct.pack('>I', len(ping)) + ping
        self._quic.send_stream_data(self.stream_control, framed_ping, end_stream=False)
        self.transmit()
        self.stream_stats[self.stream_control].bytes_sent += len(framed_ping)
        self.stream_stats[self.stream_control].messages_sent += 1
        
        # Wait for pong (with timeout)
        start = time.time()
        while seq in self._ping_times and (time.time() - start) < 5.0:
            await asyncio.sleep(0.01)
        
        if seq not in self._ping_times:
            return self.stream_stats[self.stream_control].last_rtt_ms
        return None
    
    def send_chat(self, text: str, from_peer: str):
        """Send chat message"""
        import struct
        
        msg = json.dumps({
            'type': MSG_CHAT,
            'from': from_peer,
            'text': text,
            'ts': time.time()
        }).encode()
        
        # Frame with length prefix
        framed_msg = struct.pack('>I', len(msg)) + msg
        self._quic.send_stream_data(self.stream_chat, framed_msg, end_stream=False)
        self.transmit()
        self.stream_stats[self.stream_chat].bytes_sent += len(framed_msg)
        self.stream_stats[self.stream_chat].messages_sent += 1
    
    async def send_file(self, filepath: str, file_id: str, chunk_size: int = 16384):
        """Send file over file stream with length-prefix framing"""
        import struct
        
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        
        # Send file start metadata with length prefix
        start_msg = json.dumps({
            'type': MSG_FILE_START,
            'file_id': file_id,
            'filename': filename,
            'size': file_size
        }).encode()
        # Frame: 4-byte length (big-endian) + data
        framed_start = struct.pack('>I', len(start_msg)) + start_msg
        self._quic.send_stream_data(self.stream_file, framed_start, end_stream=False)
        self.transmit()
        
        # Send file chunks with length prefix
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                framed_chunk = struct.pack('>I', len(chunk)) + chunk
                self._quic.send_stream_data(self.stream_file, framed_chunk, end_stream=False)
                self.transmit()
                self.stream_stats[self.stream_file].bytes_sent += len(chunk)
                await asyncio.sleep(0.001)  # Small delay to prevent overwhelming
        
        # Send file end with length prefix
        end_msg = json.dumps({
            'type': MSG_FILE_END,
            'file_id': file_id
        }).encode()
        framed_end = struct.pack('>I', len(end_msg)) + end_msg
        self._quic.send_stream_data(self.stream_file, framed_end, end_stream=False)
        self.transmit()
        
        logger.info(f"File sent: {filename} ({file_size} bytes)")
    
    def get_stats(self) -> Dict[int, dict]:
        """Get stream statistics"""
        return {
            stream_id: {
                'bytes_sent': stats.bytes_sent,
                'bytes_received': stats.bytes_received,
                'messages_sent': stats.messages_sent,
                'messages_received': stats.messages_received,
                'last_rtt_ms': stats.last_rtt_ms,
                'avg_rtt_ms': sum(stats.rtt_samples) / len(stats.rtt_samples) if stats.rtt_samples else 0
            }
            for stream_id, stats in self.stream_stats.items()
        }


class QuicPeer:
    """High-level QUIC peer manager"""
    
    def __init__(self, peer_id: str, cert_file: str, key_file: str,
                 ticket_store_file: Optional[str] = None):
        self.peer_id = peer_id
        self.cert_file = cert_file
        self.key_file = key_file
        self.ticket_store = SessionTicketStore(ticket_store_file)
        self.protocol: Optional[QuicPeerProtocol] = None
        self._server = None
        self._connection = None  # Holds the connection context manager
        self._target_peer_addr: Optional[Tuple[str, int]] = None  # Store target peer address for ticket association

    def _create_client_config(self) -> QuicConfiguration:
        """Create QUIC configuration for client mode"""
        config = QuicConfiguration(
            is_client=True,
            alpn_protocols=["nat-traversal"],
        )
        # Use a stable name for SNI / certificate validation across hairpin/local IP flows.
        config.server_name = "localhost"
        # Trust the generated self-signed certificate and require verification.
        config.load_verify_locations(self.cert_file)
        config.verify_mode = ssl.CERT_REQUIRED
        
        # Try to load existing session ticket for this peer (for 0-RTT)
        if self._target_peer_addr:
            logger.debug(f"Looking for existing ticket for {self._target_peer_addr[0]}:{self._target_peer_addr[1]}")
            ticket = self.ticket_store.get_ticket_for_peer(self._target_peer_addr)
            if ticket:
                config.session_ticket = ticket
                logger.info(f"✓ Loaded session ticket for 0-RTT to {self._target_peer_addr[0]}:{self._target_peer_addr[1]}")
            else:
                logger.debug(f"No existing ticket for {self._target_peer_addr[0]}:{self._target_peer_addr[1]} - will perform full handshake")
        
        # Enable 0-RTT - callback to store new tickets from server
        config.session_ticket_handler = self.ticket_store.add

        return config
    
    def _create_server_config(self) -> QuicConfiguration:
        """Create QUIC configuration for server mode"""
        config = QuicConfiguration(
            is_client=False,
            alpn_protocols=["nat-traversal"],
        )
        config.load_cert_chain(self.cert_file, self.key_file)
        
        # Issue session tickets for 0-RTT
        config.session_ticket_handler = self.ticket_store.add
        
        return config
    
    async def connect(self, host: str, port: int, 
                      local_port: Optional[int] = None, auth_token: str = None) -> QuicPeerProtocol:
        """
        Connect to a QUIC peer.
        
        Args:
            host: Remote host
            port: Remote port
            local_port: Local port to bind (for hole punching, use same port)
            auth_token: Optional auth token
        Returns:
            QuicPeerProtocol instance
        """

        peer_addr = (host, port)
        self._target_peer_addr = peer_addr

        config = self._create_client_config()
        
        logger.info(f"Connecting to {host}:{port}")

        if auth_token:
            logger.info(f"Connecting with auth token, expires in {self._auth_token['expiry'] - time.time()}s")
        
        start_time = time.time()
        
        # Create protocol factory that passes is_client=True
        def client_protocol_factory(*args, **kwargs):
            return QuicPeerProtocol(*args, is_client=True, **kwargs)
        
        # Use connect() without context manager to keep connection alive
        # The connection object is stored and must be closed explicitly via close()
        self._connection = connect(
            host, port,
            configuration=config,
            create_protocol=client_protocol_factory,
            local_port=local_port or 0
        )
        
        self.protocol = await self._connection.__aenter__()
        self.protocol.peer_id = self.peer_id
        
        await self.protocol.connected.wait()
        
        connect_time = (time.time() - start_time) * 1000
        is_0rtt = self.protocol.early_data_accepted
        
        logger.info(f"Connected in {connect_time:.1f}ms | 0-RTT={is_0rtt}")
        
        # After successful connection, move ticket from placeholder to peer address
        if self._target_peer_addr:
            # Get the placeholder ticket that was stored during handshake
            placeholder_entry = self.ticket_store.ticket_entries.pop(("unknown", 0), None)
            if placeholder_entry:
                self.ticket_store.ticket_entries[self._target_peer_addr] = placeholder_entry
                placeholder_entry.peer_addr = self._target_peer_addr
                logger.info(f"Associated session ticket with peer {self._target_peer_addr[0]}:{self._target_peer_addr[1]}")
                if self.ticket_file:
                    self.ticket_store._save_tickets()
        
        # Cleanup expired tickets
        self.ticket_store.cleanup_expired()

        return self.protocol
    
    async def listen(self, host: str, port: int,
                     on_connection: Optional[Callable[[QuicPeerProtocol], None]] = None):
        """
        Listen for incoming QUIC connections.
        
        Args:
            host: Bind address
            port: Bind port (use same port as hole punching)
            on_connection: Callback when peer connects
        """
        config = self._create_server_config()
        
        logger.info(f"Listening on {host}:{port}")
        
        def protocol_factory(*args, **kwargs):
            protocol = QuicPeerProtocol(*args, is_client=False, **kwargs)
            protocol.peer_id = self.peer_id
            if on_connection:
                asyncio.create_task(self._wait_and_notify(protocol, on_connection))
            return protocol
        
        self._server = await serve(
            host, port,
            configuration=config,
            create_protocol=protocol_factory
        )
        
        return self._server
    
    async def _wait_and_notify(self, protocol: QuicPeerProtocol, callback: Callable):
        """Wait for connection and notify callback"""
        await protocol.connected.wait()
        callback(protocol)
    
    async def close(self):
        """Close connections"""
        if self._connection:
            try:
                await self._connection.__aexit__(None, None, None)
            except Exception as e:
                logger.debug(f"Error closing connection: {e}")
            self._connection = None
        if self.protocol:
            self.protocol.close()
        if self._server:
            self._server.close()


def generate_self_signed_cert(cert_file: str, key_file: str, common_name: str = "nat-traversal"):
    """Generate self-signed certificate for QUIC"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime
    
    # Generate key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    # Write key
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    logger.info(f"Generated certificate: {cert_file}, {key_file}")


# Need ipaddress for cert generation
import ipaddress


async def main():
    """Test QUIC peer"""
    import argparse
    parser = argparse.ArgumentParser(description='QUIC Peer Test')
    parser.add_argument('--mode', choices=['client', 'server'], required=True)
    parser.add_argument('--peer-id', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=4433)
    parser.add_argument('--cert', default='cert.pem')
    parser.add_argument('--key', default='key.pem')
    args = parser.parse_args()
    
    # Generate certs if needed
    if not os.path.exists(args.cert):
        generate_self_signed_cert(args.cert, args.key)
    
    peer = QuicPeer(args.peer_id, args.cert, args.key)
    
    if args.mode == 'server':
        await peer.listen(args.host, args.port)
        print(f"Server listening on {args.host}:{args.port}")
        await asyncio.Future()  # Run forever
    else:
        protocol = await peer.connect(args.host, args.port)
        
        # Test ping
        rtt = await protocol.send_ping()
        print(f"Ping RTT: {rtt:.1f}ms")
        
        # Test chat
        protocol.on_chat_message = lambda f, t: print(f"[{f}]: {t}")
        protocol.send_chat("Hello from client!", args.peer_id)
        
        await asyncio.sleep(5)


if __name__ == '__main__':
    asyncio.run(main())
