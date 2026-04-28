"""
Metrics Collection
Tracks:
1. NAT type detected
2. Hole punch success/failure + time taken
3. Whether relay fallback was used
4. RTT per stream (ping/pong every 5 seconds)
5. Bytes transferred per stream

Exposes via /metrics HTTP endpoint.
"""

import asyncio
import json
import time
import threading
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import partial
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('metrics')


@dataclass
class ConnectionMetrics:
    """Metrics for a single connection"""
    peer_id: str
    target_peer_id: str
    
    # NAT classification
    nat_type: str = "unknown"
    nat_confidence: str = "unknown"
    mapped_addr: Optional[tuple] = None
    
    # Hole punch
    hole_punch_success: bool = False
    hole_punch_time_ms: float = 0.0
    hole_punch_attempts: int = 0
    
    # Relay fallback
    using_relay: bool = False
    relay_session_id: Optional[str] = None
    
    # Connection timing
    connection_start_time: float = 0.0
    connection_established_time: float = 0.0
    is_0rtt: bool = False
    
    # Stream stats
    stream_stats: Dict[int, dict] = field(default_factory=dict)
    
    # RTT samples
    rtt_samples: List[float] = field(default_factory=list)
    last_rtt_ms: float = 0.0
    avg_rtt_ms: float = 0.0
    min_rtt_ms: float = 0.0
    max_rtt_ms: float = 0.0
    
    # Byte counters
    total_bytes_sent: int = 0
    total_bytes_received: int = 0


class MetricsCollector:
    """Collects and manages metrics for all connections"""
    
    def __init__(self, peer_id: str, metrics_file: str = "metrics.json"):
        self.peer_id = peer_id
        self.metrics_file = metrics_file
        self.connections: Dict[str, ConnectionMetrics] = {}
        self._lock = threading.Lock()
        self._ping_tasks: Dict[str, asyncio.Task] = {}
    
    def start_connection(self, target_peer_id: str) -> ConnectionMetrics:
        """Start tracking a new connection"""
        with self._lock:
            metrics = ConnectionMetrics(
                peer_id=self.peer_id,
                target_peer_id=target_peer_id,
                connection_start_time=time.time()
            )
            self.connections[target_peer_id] = metrics
            logger.debug(f"[METRICS] Started tracking connection to {target_peer_id}")
            return metrics
    
    def get_connection(self, target_peer_id: str) -> Optional[ConnectionMetrics]:
        """Get metrics for a connection"""
        return self.connections.get(target_peer_id)
    
    def record_nat_classification(self, target_peer_id: str, nat_type: str, 
                                   confidence: str, mapped_addr: tuple):
        """Record NAT classification results"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.nat_type = nat_type
                m.nat_confidence = confidence
                m.mapped_addr = mapped_addr
                self._save()
    
    def record_hole_punch(self, target_peer_id: str, success: bool, 
                          time_ms: float, attempts: int):
        """Record hole punch result"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.hole_punch_success = success
                m.hole_punch_time_ms = time_ms
                m.hole_punch_attempts = attempts
                self._save()
    
    def record_relay_fallback(self, target_peer_id: str, session_id: str):
        """Record relay fallback activation"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.using_relay = True
                m.relay_session_id = session_id
                self._save()
    
    def record_connection_established(self, target_peer_id: str, is_0rtt: bool = False):
        """Record successful connection establishment"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.connection_established_time = time.time()
                m.is_0rtt = is_0rtt
                self._save()
    
    def record_rtt(self, target_peer_id: str, rtt_ms: float):
        """Record an RTT sample"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.rtt_samples.append(rtt_ms)
                m.last_rtt_ms = rtt_ms
                
                # Update statistics
                if m.rtt_samples:
                    m.avg_rtt_ms = sum(m.rtt_samples) / len(m.rtt_samples)
                    m.min_rtt_ms = min(m.rtt_samples)
                    m.max_rtt_ms = max(m.rtt_samples)
                
                self._save()
    
    def record_bytes(self, target_peer_id: str, stream_id: int, 
                     sent: int = 0, received: int = 0):
        """Record bytes transferred"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                
                if stream_id not in m.stream_stats:
                    m.stream_stats[stream_id] = {
                        'bytes_sent': 0,
                        'bytes_received': 0
                    }
                
                m.stream_stats[stream_id]['bytes_sent'] += sent
                m.stream_stats[stream_id]['bytes_received'] += received
                m.total_bytes_sent += sent
                m.total_bytes_received += received
    
    def update_stream_stats(self, target_peer_id: str, stream_stats: Dict[int, dict]):
        """Update stream statistics from QUIC protocol"""
        with self._lock:
            if target_peer_id in self.connections:
                m = self.connections[target_peer_id]
                m.stream_stats = stream_stats
                
                # Update totals
                m.total_bytes_sent = sum(s.get('bytes_sent', 0) for s in stream_stats.values())
                m.total_bytes_received = sum(s.get('bytes_received', 0) for s in stream_stats.values())
                
                self._save()
    
    async def start_ping_loop(self, target_peer_id: str, protocol, interval: float = 5.0):
        """Start periodic ping loop for RTT measurement"""
        async def ping_loop():
            while True:
                try:
                    rtt = await protocol.send_ping()
                    if rtt is not None:
                        self.record_rtt(target_peer_id, rtt)
                    await asyncio.sleep(interval)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Ping error: {e}")
                    await asyncio.sleep(interval)
        
        task = asyncio.create_task(ping_loop())
        self._ping_tasks[target_peer_id] = task
        return task
    
    def stop_ping_loop(self, target_peer_id: str):
        """Stop ping loop for a connection"""
        if target_peer_id in self._ping_tasks:
            self._ping_tasks[target_peer_id].cancel()
            del self._ping_tasks[target_peer_id]
    
    def _save(self):
        """Save metrics to JSON file"""
        try:
            data = {
                'peer_id': self.peer_id,
                'timestamp': time.time(),
                'connections': {}
            }
            
            for peer_id, metrics in self.connections.items():
                data['connections'][peer_id] = {
                    'target_peer_id': metrics.target_peer_id,
                    'nat_type': metrics.nat_type,
                    'nat_confidence': metrics.nat_confidence,
                    'mapped_addr': list(metrics.mapped_addr) if metrics.mapped_addr else None,
                    'hole_punch_success': metrics.hole_punch_success,
                    'hole_punch_time_ms': metrics.hole_punch_time_ms,
                    'hole_punch_attempts': metrics.hole_punch_attempts,
                    'using_relay': metrics.using_relay,
                    'relay_session_id': metrics.relay_session_id,
                    'connection_time_ms': (metrics.connection_established_time - metrics.connection_start_time) * 1000 if metrics.connection_established_time else 0,
                    'is_0rtt': metrics.is_0rtt,
                    'rtt': {
                        'last_ms': metrics.last_rtt_ms,
                        'avg_ms': metrics.avg_rtt_ms,
                        'min_ms': metrics.min_rtt_ms,
                        'max_ms': metrics.max_rtt_ms,
                        'sample_count': len(metrics.rtt_samples)
                    },
                    'bytes': {
                        'total_sent': metrics.total_bytes_sent,
                        'total_received': metrics.total_bytes_received,
                        'by_stream': metrics.stream_stats
                    }
                }
            
            with open(self.metrics_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")
    
    def get_json(self) -> str:
        """Get metrics as JSON string"""
        with self._lock:
            self._save()
            try:
                with open(self.metrics_file, 'r') as f:
                    return f.read()
            except:
                return '{}'
    
    def get_summary(self) -> dict:
        """Get summary of all connections"""
        with self._lock:
            summary = {
                'peer_id': self.peer_id,
                'active_connections': len(self.connections),
                'connections': []
            }
            
            for peer_id, m in self.connections.items():
                summary['connections'].append({
                    'target': peer_id,
                    'nat_type': m.nat_type,
                    'using_relay': m.using_relay,
                    'hole_punch_success': m.hole_punch_success,
                    'rtt_ms': m.last_rtt_ms,
                    'bytes_sent': m.total_bytes_sent,
                    'bytes_received': m.total_bytes_received
                })
            
            return summary


class MetricsHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint"""
    
    def __init__(self, collector: MetricsCollector, *args, **kwargs):
        self.collector = collector
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(self.collector.get_json().encode())
        
        elif self.path == '/metrics/summary':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(self.collector.get_summary(), indent=2).encode())
        
        elif self.path == '/':
            # Simple HTML dashboard
            html = self._generate_html()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def _generate_html(self) -> str:
        """Generate simple HTML dashboard"""
        summary = self.collector.get_summary()
        
        html = """<!DOCTYPE html>
<html>
<head>
    <title>NAT Traversal Metrics</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; }
        .card { background: #16213e; border-radius: 8px; padding: 15px; margin: 10px 0; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; color: #00d4ff; }
        .metric-label { font-size: 12px; color: #888; }
        .success { color: #00ff88; }
        .failure { color: #ff4444; }
        .relay { color: #ffaa00; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #00d4ff; }
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>NAT Traversal Metrics</h1>
    <div class="card">
        <div class="metric">
            <div class="metric-value">""" + summary['peer_id'] + """</div>
            <div class="metric-label">Peer ID</div>
        </div>
        <div class="metric">
            <div class="metric-value">""" + str(summary['active_connections']) + """</div>
            <div class="metric-label">Active Connections</div>
        </div>
    </div>
    <div class="card">
        <h2>Connections</h2>
        <table>
            <tr>
                <th>Target</th>
                <th>NAT Type</th>
                <th>Hole Punch</th>
                <th>Mode</th>
                <th>RTT (ms)</th>
                <th>Bytes Sent</th>
                <th>Bytes Received</th>
            </tr>
"""
        
        for conn in summary['connections']:
            punch_class = 'success' if conn['hole_punch_success'] else 'failure'
            mode = 'Relay' if conn['using_relay'] else 'Direct'
            mode_class = 'relay' if conn['using_relay'] else 'success'
            
            html += f"""
            <tr>
                <td>{conn['target']}</td>
                <td>{conn['nat_type']}</td>
                <td class="{punch_class}">{'✓' if conn['hole_punch_success'] else '✗'}</td>
                <td class="{mode_class}">{mode}</td>
                <td>{conn['rtt_ms']:.1f}</td>
                <td>{conn['bytes_sent']:,}</td>
                <td>{conn['bytes_received']:,}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    <div class="card">
        <p>Raw JSON: <a href="/metrics" style="color: #00d4ff;">/metrics</a></p>
    </div>
</body>
</html>"""
        
        return html
    
    def log_message(self, format, *args):
        pass  # Suppress HTTP logging


class MetricsServer:
    """HTTP server for metrics endpoint"""
    
    def __init__(self, collector: MetricsCollector, host: str = '0.0.0.0', port: int = 9090):
        self.collector = collector
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start metrics server in background thread"""
        handler = partial(MetricsHTTPHandler, self.collector)
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Metrics server started on http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop metrics server"""
        if self._server:
            self._server.shutdown()
            self._server = None


async def main():
    """Test metrics collection"""
    import argparse
    parser = argparse.ArgumentParser(description='Metrics Test')
    parser.add_argument('--peer-id', default='test-peer')
    parser.add_argument('--port', type=int, default=9090)
    args = parser.parse_args()
    
    # Create collector
    collector = MetricsCollector(args.peer_id)
    
    # Start HTTP server
    server = MetricsServer(collector, port=args.port)
    server.start()
    
    # Simulate some metrics
    collector.start_connection('peer-b')
    collector.record_nat_classification('peer-b', 'full_cone', 'high', ('1.2.3.4', 12345))
    collector.record_hole_punch('peer-b', True, 150.5, 3)
    collector.record_connection_established('peer-b', is_0rtt=False)
    
    # Simulate RTT samples
    for i in range(10):
        collector.record_rtt('peer-b', 50 + i * 2)
        await asyncio.sleep(1)
    
    print(f"Metrics available at http://localhost:{args.port}/")
    print("Press Ctrl+C to stop")
    
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        server.stop()


if __name__ == '__main__':
    asyncio.run(main())
