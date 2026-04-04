#!/usr/bin/env python3
"""
Interactive demo of NAT Traversal system.
Shows step-by-step how hole punching and relay fallback work.
"""

import asyncio
import subprocess
import sys
import time
import json
from pathlib import Path


class Demo:
    def __init__(self):
        self.processes = []
    
    def print_section(self, title):
        """Print a formatted section header"""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70)
    
    def print_step(self, step_num, description):
        """Print a numbered step"""
        print(f"\n[Step {step_num}] {description}")
    
    def wait_for_input(self):
        """Wait for user to press Enter"""
        input("\nPress Enter to continue...")
    
    def start_process(self, cmd, name):
        """Start a subprocess and track it"""
        print(f"\nStarting {name}...")
        proc = subprocess.Popen(cmd, shell=True)
        self.processes.append(proc)
        return proc
    
    def stop_all(self):
        """Stop all running processes"""
        print("\nCleaning up...")
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                proc.kill()
    
    def run(self):
        """Run the demo"""
        try:
            self.print_section("NAT Traversal Demonstration")
            
            print("""
This demo shows how NAT traversal with UDP hole punching and relay fallback works.

We will run:
1. Rendezvous Server - coordinates peer discovery and token auth
2. Peer A (Alice) - listener
3. Peer B (Bob) - initiator connecting to Alice

The system will demonstrate:
- NAT type classification
- Connection token exchange
- UDP hole punching attempt
- Relay fallback when hole punching fails
- Metrics collection
            """)
            
            self.wait_for_input()
            
            # Step 1: Start server
            self.print_step(1, "Starting Rendezvous Server")
            print("""
The rendezvous server:
- Listens on UDP 3478, 3479 for STUN probes (NAT classification)
- Listens on WebSocket 8765 for peer signaling and tokens
- Manages relay when hole punching fails
            """)
            self.start_process('python server/rendezvous.py --host 127.0.0.1', 'Rendezvous Server')
            time.sleep(2)  # Give server time to start
            
            self.wait_for_input()
            
            # Step 2: Start Alice
            self.print_step(2, "Starting Peer A (Alice) - Listener Mode")
            print("""
Alice will:
- Probe the server's two STUN ports to classify its NAT type
- Register with the server
- Wait for incoming connections
            """)
            self.start_process('python peer/main.py --server 127.0.0.1 --peer-id alice --metrics-port 9091', 'Peer A (Alice)')
            time.sleep(3)  # Give Alice time to classify NAT and register
            
            self.wait_for_input()
            
            # Step 3: Start Bob
            self.print_step(3, "Starting Peer B (Bob) - Connector Mode")
            print("""
Bob will:
- Classify its NAT type
- Request connection token from server
- Send connect request with Alice's ID
- Attempt UDP hole punching with Alice
- Fall back to relay if hole punch fails
- Send chat message to Alice
            """)
            self.start_process('python peer/main.py --server 127.0.0.1 --peer-id bob --connect alice --metrics-port 9092', 'Peer B (Bob)')
            time.sleep(4)
            
            print("""
Watch the output above. You should see:
- NAT classification results (full_cone, port_restricted, symmetric, etc.)
- Connection token exchange
- Hole punch attempt (will fail on localhost and fall back to relay)
- Relay session established
            """)
            
            self.wait_for_input()
            
            # Step 4: Check metrics
            self.print_step(4, "Checking Metrics")
            print("""
The system exposes metrics via HTTP endpoints:
- Alice: http://localhost:9091/
- Bob: http://localhost:9092/

These show:
- NAT type detected
- Whether hole punch succeeded
- Whether relay fallback was used
- RTT (round-trip time)
- Bytes transferred per stream

Try visiting these URLs in your browser to see the real-time dashboard.
            """)
            
            self.wait_for_input()
            
            # Step 5: Interaction
            self.print_step(5, "Interactive Chat")
            print("""
Now you can interact with the peers:

In either peer terminal, you can:
- Type messages and press Enter to chat
- Type /stats to see connection statistics
- Type /file <path> to send a file (direct mode only)
- Type /quit to exit

Try sending messages between Alice and Bob!

Note: On localhost, the connection will use relay mode because hole punching
requires different external IPs. In a real NAT scenario with different networks,
hole punching would succeed for most NAT types.
            """)
            
            print("""
Keep the demo running to continue testing.
Watch the logs for:
- "Hole punch SUCCESS" or "Hole punch FAILED"
- "Relay mode" activation
- Connection establishment messages
            """)
            
            print("\n(Processes running. Type Ctrl+C in any peer terminal to quit.)")
            print("(This demo window will wait...)")
            
            # Keep demo alive
            while True:
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\nDemo interrupted by user")
        
        finally:
            self.stop_all()
            print("Demo ended.")


def main():
    """Main entry point"""
    # Check if required files exist
    required_files = ['server/rendezvous.py', 'peer/main.py', 'certs/cert.pem']
    
    for file in required_files:
        if not Path(file).exists():
            print(f"Error: Required file not found: {file}")
            print("Please run: python scripts/gen_certs.py")
            return 1
    
    demo = Demo()
    try:
        demo.run()
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        demo.stop_all()


if __name__ == '__main__':
    sys.exit(main())
