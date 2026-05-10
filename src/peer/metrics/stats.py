import asyncio
import json
import logging
import time
from typing import Optional

from peer.connection.relay import RelayPeerAdapter

logger = logging.getLogger('stats_manager')


class StatManager:
    
    def __init__(
        self,
        peer_id: str,
        metrics,             # MetricsCollector instance
        signaling_manager,   # SignalingManager instance
        protocol_lock: asyncio.Lock,  # shared lock from PeerNode
    ):
        # Identity & service references
        self.peer_id = peer_id
        self.metrics = metrics
        self.signaling_manager = signaling_manager

        # Shared lock (same object as PeerNode._protocol_lock)
        self._protocol_lock = protocol_lock

        # Reference to ConnectionManager (set by PeerNode after construction)
        self.conn_manager = None

        # Relay RTT ping tracking (owned by StatManager)
        self._relay_ping_seq: int = 0
        self._relay_ping_times: dict = {}
        self._relay_last_rtt_ms: float = 0.0
        self._relay_rtt_samples: list = []
        
    async def _sync_stats_loop(self, target_peer_id: str):
        """Periodically sync protocol stats into the metrics collector."""
        try:
            while True:
                await asyncio.sleep(5.0)
                async with self._protocol_lock:
                    proto = self.conn_manager.protocol if self.conn_manager else None
                if proto:
                    stats = proto.get_stats()
                    self.metrics.update_stream_stats(target_peer_id, stats)
                else:
                    break  # No longer active
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Stats sync loop ended: {e}")

    async def _relay_ping_loop(self, target_peer_id: str, interval: float = 5.0):
        """Periodic ping loop for listener-side relay RTT measurement via signalling websocket."""
        try:
            while self.conn_manager and self.conn_manager.using_relay:
                await asyncio.sleep(interval)
                if not (self.conn_manager and self.conn_manager.using_relay):
                    break
                self._relay_ping_seq += 1
                seq = self._relay_ping_seq
                self._relay_ping_times[seq] = time.time()
                await self.signaling_manager._send_relay_frame(target_peer_id, json.dumps({
                    'type': 'control',
                    'control_type': 'ping',
                    'from': self.peer_id,
                    'seq': seq,
                    'ts': time.time()
                }).encode())
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Relay ping loop ended: {e}")

    def get_stats(self):
        proto = self.conn_manager.protocol if self.conn_manager else None
        using_relay = self.conn_manager.using_relay if self.conn_manager else False
        relay_target = self.conn_manager.relay_target_peer_id if self.conn_manager else None
        if proto:
            stats = proto.get_stats()
            # For relay mode with adapter, sync stats to metrics collector
            if isinstance(proto, RelayPeerAdapter):
                for target_id in list(self.metrics.connections.keys()):
                    self.metrics.update_stream_stats(target_id, stats)
            return stats
        # Listener-side relay: build stats from metrics collector
        if using_relay and relay_target:
            conn = self.metrics.get_connection(relay_target)
            if conn:
                avg_rtt = (sum(self._relay_rtt_samples) / len(self._relay_rtt_samples)) if self._relay_rtt_samples else 0.0
                return {
                    0: {
                        'bytes_sent': 0, 'bytes_received': 0,
                        'messages_sent': 0, 'messages_received': 0,
                        'last_rtt_ms': self._relay_last_rtt_ms,
                        'avg_rtt_ms': avg_rtt,
                        'is_relay': True
                    },
                    4: {
                        'bytes_sent': conn.stream_stats.get(4, {}).get('bytes_sent', 0) if conn.stream_stats else conn.total_bytes_sent,
                        'bytes_received': conn.stream_stats.get(4, {}).get('bytes_received', 0) if conn.stream_stats else conn.total_bytes_received,
                        'messages_sent': conn.stream_stats.get(4, {}).get('messages_sent', 0) if conn.stream_stats else conn.total_messages_sent,
                        'messages_received': conn.stream_stats.get(4, {}).get('messages_received', 0) if conn.stream_stats else conn.total_messages_received,
                        'is_relay': True
                    },
                    8: {
                        'bytes_sent': 0, 'bytes_received': 0,
                        'messages_sent': 0, 'messages_received': 0,
                        'disabled': True, 'reason': 'File transfer disabled in relay mode'
                    }
                }
        return {}