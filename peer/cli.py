import asyncio
import os
import json
import time
import uuid
import argparse
from pathlib import Path
from typing import Optional, TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from peer.main import PeerNode

async def interactive_mode(node: 'PeerNode', target_peer_id: str = None):
    """Interactive chat mode"""
    
    def on_chat(from_peer: str, text: str):
        print(f"\n[{from_peer}]: {text}")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)
    
    def on_connected(peer_id: str, is_relay: bool):
        mode = "relay" if is_relay else "direct"
        print(f"\n*** Connected to {peer_id} ({mode} mode) ***")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)

    def on_file_received(file_id: str, file_data: bytes, metadata: dict):
        filename = os.path.basename(metadata.get('filename', f"received_{file_id}.bin"))
        output_dir = Path("received_files") / node.peer_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / filename

        if output_path.exists():
            output_path = output_dir / f"{file_id}_{filename}"

        with open(output_path, 'wb') as f:
            f.write(file_data)

        print(f"\n*** File received: {filename} ({len(file_data)} bytes) -> {output_path} ***")
        print(f"\r[{node.peer_id}]> ", end='', flush=True)
    
    node.on_chat_message = on_chat
    node.on_connected = on_connected
    node.on_file_received = on_file_received
    
    if target_peer_id:
        # Initiator mode - connect to peer with retries
        max_retries = 5
        retry_delay = 2.0  # seconds
        
        for attempt in range(1, max_retries + 1):
            print(f"Connecting to peer: {target_peer_id} (attempt {attempt}/{max_retries})...")
            success = await node.connect_to_peer(target_peer_id)
            if success:
                break
            
            if attempt < max_retries:
                print(f"Connection failed, retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
            else:
                print("Failed to connect after all retries")
                return
    else:
        # Listener mode - wait for connections
        print("\rWaiting for incoming connections...")
        asyncio.create_task(node.listen_for_connections())
    
    # Interactive chat loop
    print(f"\nType messages and press Enter. Commands: /stats, /file <path>, /quit")
    
    loop = asyncio.get_event_loop()
    
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input(f"\r[{node.peer_id}]> "))
            
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
                await node.send_chat(line)
        
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


async def run():
    from peer.main import PeerNode
    
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

