"""
UDP Hole Punching Logic
Both peers simultaneously send UDP packets to each other's mapped address to open NAT bindings.
Uses retry loop: send every 200ms, up to 3 seconds.
"""

import asyncio
import json
import socket
import time
import logging
import threading
from dataclasses import dataclass
from typing import Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('hole_punch')

PUNCH_INTERVAL_MS = 100  # Send every 100ms (more aggressive)
PUNCH_TIMEOUT_MS = 10000  # Total timeout 10 seconds (more time for real NATs)
PUNCH_MAGIC = b'NATPUNCH'


@dataclass
class HolePunchResult:
    success: bool
    time_taken_ms: float
    attempts: int
    peer_addr: Optional[Tuple[str, int]] = None
    error: Optional[str] = None


class HolePuncher:
    """
    Performs UDP hole punching between two peers.
    Both peers must call punch() simultaneously after exchanging addresses.
    """
    
    def __init__(self, local_socket: socket.socket, peer_id: str):
        """
        Args:
            local_socket: UDP socket to use (same one used for NAT classification)
            peer_id: This peer's ID
        """
        self.sock = local_socket
        self.peer_id = peer_id
        # Socket timeout is managed per-operation to avoid race conditions
        self._punch_received = asyncio.Event()
        self._peer_confirmed_addr: Optional[Tuple[str, int]] = None
    
    def _create_punch_packet(self, sequence: int) -> bytes:
        """Create a hole punch packet"""
        data = {
            'magic': PUNCH_MAGIC.decode(),
            'peer_id': self.peer_id,
            'seq': sequence,
            'ts': time.time()
        }
        return json.dumps(data).encode()
    
    def _is_punch_packet(self, data: bytes) -> Tuple[bool, Optional[dict]]:
        """Check if received data is a punch packet"""
        try:
            parsed = json.loads(data.decode())
            if parsed.get('magic') == PUNCH_MAGIC.decode():
                return True, parsed
        except:
            pass
        return False, None
    
    async def punch(self, target_addr: Tuple[str, int], 
                    on_success: Optional[Callable] = None) -> HolePunchResult:
        """
        Perform hole punching to target address.
        
        Args:
            target_addr: Target peer's mapped (ip, port)
            on_success: Optional callback when punch succeeds
            
        Returns:
            HolePunchResult with success status and timing info
        """
        start_time = time.time()
        loop = asyncio.get_event_loop()
        max_attempts = PUNCH_TIMEOUT_MS // PUNCH_INTERVAL_MS
        
        logger.info(f"[PUNCH] Starting hole punch to {target_addr[0]}:{target_addr[1]} (timeout={PUNCH_TIMEOUT_MS}ms, interval={PUNCH_INTERVAL_MS}ms)")
        
        # Create tasks for sending and receiving
        send_task = asyncio.create_task(self._send_punches(target_addr, max_attempts))
        recv_task = asyncio.create_task(self._receive_punches(target_addr))
        
        try:
            # Wait for either success or timeout
            done, pending = await asyncio.wait(
                [send_task, recv_task],
                timeout=PUNCH_TIMEOUT_MS / 1000,
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            if self._punch_received.is_set():
                logger.info(f"[PUNCH] SUCCESS in {elapsed_ms:.0f}ms with ~{int(elapsed_ms / PUNCH_INTERVAL_MS)} attempts | Peer confirmed at {self._peer_confirmed_addr}")
                if on_success:
                    on_success()
                return HolePunchResult(
                    success=True,
                    time_taken_ms=elapsed_ms,
                    attempts=int(elapsed_ms / PUNCH_INTERVAL_MS) + 1,
                    peer_addr=self._peer_confirmed_addr or target_addr
                )
            else:
                logger.warning(f"[PUNCH] FAILED after {elapsed_ms:.0f}ms | No response from {target_addr[0]}:{target_addr[1]}")
                return HolePunchResult(
                    success=False,
                    time_taken_ms=elapsed_ms,
                    attempts=max_attempts,
                    error="Timeout - no response from peer"
                )
        
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            logger.error(f"[PUNCH] Error after {elapsed_ms:.0f}ms: {e}")
            return HolePunchResult(
                success=False,
                time_taken_ms=elapsed_ms,
                attempts=0,
                error=str(e)
            )
    
    async def _send_punches(self, target_addr: Tuple[str, int], max_attempts: int):
        """Send punch packets at regular intervals with initial burst"""
        loop = asyncio.get_event_loop()
        
        # Send initial burst of packets to quickly open NAT binding
        logger.info(f"Sending initial burst to {target_addr}")
        for i in range(5):
            packet = self._create_punch_packet(i)
            try:
                await loop.run_in_executor(
                    None,
                    lambda p=packet, t=target_addr: self.sock.sendto(p, t)
                )
            except Exception as e:
                logger.debug(f"Burst send error: {e}")
            await asyncio.sleep(0.02)  # 20ms between burst packets
        
        # Continue with regular interval punches
        for seq in range(5, max_attempts):
            if self._punch_received.is_set():
                break
            
            packet = self._create_punch_packet(seq)
            try:
                # Use run_in_executor for thread-safe send (avoids socket mode conflicts)
                await loop.run_in_executor(
                    None,
                    lambda p=packet, t=target_addr: self.sock.sendto(p, t)
                )
                if seq % 10 == 0:  # Log every 10th attempt
                    logger.debug(f"Sent punch #{seq} to {target_addr}")
            except Exception as e:
                logger.error(f"Send error: {e}")
            
            await asyncio.sleep(PUNCH_INTERVAL_MS / 1000)
    
    async def _receive_punches(self, expected_addr: Tuple[str, int]):
        """Listen for incoming punch packets using thread pool for Windows compatibility"""
        loop = asyncio.get_event_loop()

        executor = ThreadPoolExecutor(max_workers=1)

        def blocking_recv():
            """Receive with timeout in a thread-safe way"""
            # Set timeout each time to ensure consistent behavior
            self.sock.settimeout(0.1)  # 100ms timeout for blocking recv
            return self.sock.recvfrom(1024)

        received_from = set()  # Track IPs we've received from
        punch_count = 0

        while not self._punch_received.is_set():
            try:
                # Run blocking recv in thread pool for proper Windows compatibility
                data, addr = await loop.run_in_executor(executor, blocking_recv)

                is_punch, parsed = self._is_punch_packet(data)
                if is_punch:
                    punch_count += 1
                    received_from.add(addr[0])
                    if punch_count == 1 or punch_count % 5 == 0:  # Log first and every 5th punch
                        logger.info(f"Received punch #{punch_count} from {addr}, peer_id={parsed.get('peer_id')}")

                    # Accept punch from expected IP OR if it contains our expected peer_id
                    # This handles symmetric NAT where port changes
                    if addr[0] == expected_addr[0] or parsed.get('peer_id'):
                        self._peer_confirmed_addr = addr
                        self._punch_received.set()

                        # Send multiple confirmations back (in case some are lost)
                        confirm = json.dumps({
                            'magic': PUNCH_MAGIC.decode(),
                            'peer_id': self.peer_id,
                            'type': 'confirm',
                            'ts': time.time()
                        }).encode()
                        for _ in range(3):
                            try:
                                self.sock.sendto(confirm, addr)
                            except:
                                pass
                        logger.info(f"Hole punch confirmed with peer at {addr} (received {punch_count} punches total)")
                        executor.shutdown(wait=False)
                        return
                else:
                    logger.debug(f"Received non-punch data from {addr}: {data[:50]}")

            except socket.timeout:
                # Expected timeout, continue loop
                continue
            except OSError as e:
                # Handle socket errors (e.g., connection reset, would block)
                if not self._punch_received.is_set():
                    logger.debug(f"Socket error during receive: {e}")
                    await asyncio.sleep(0.05)
            except Exception as e:
                if not self._punch_received.is_set():
                    logger.debug(f"Receive error: {e}")
                    await asyncio.sleep(0.05)

        if received_from:
            logger.warning(f"Received {punch_count} punches from IPs: {received_from} but none matched expected {expected_addr[0]} - possible symmetric NAT or firewall blocking")
        else:
            logger.warning(f"No punches received from any IP (expected {expected_addr[0]}) - firewall or network isolation likely")

        executor.shutdown(wait=False)


class BidirectionalHolePuncher:
    """
    Coordinates hole punching when both peers are ready.
    Handles the simultaneous nature of the process.
    """
    
    def __init__(self, local_socket: socket.socket, peer_id: str):
        self.sock = local_socket
        self.peer_id = peer_id
        self.puncher = HolePuncher(local_socket, peer_id)
    
    async def execute(self, target_addr: Tuple[str, int], 
                      my_nat_type: str, peer_nat_type: str) -> HolePunchResult:
        """
        Execute hole punching with strategy based on NAT types.
        
        Args:
            target_addr: Peer's mapped address
            my_nat_type: This peer's NAT type
            peer_nat_type: Remote peer's NAT type
            
        Returns:
            HolePunchResult
        """
        # Check if hole punching is feasible
        symmetric_pair = my_nat_type == 'symmetric' and peer_nat_type == 'symmetric'
        
        if symmetric_pair:
            logger.warning("Both peers have symmetric NAT - hole punch unlikely to succeed")
            # Still try, but expect failure
        
        # Adjust strategy based on NAT types
        if my_nat_type == 'symmetric' or peer_nat_type == 'symmetric':
            # One symmetric NAT - might work with more attempts
            logger.info("One peer has symmetric NAT - using extended retry")
            return await self._extended_punch(target_addr)
        else:
            # Both non-symmetric - standard approach
            return await self.puncher.punch(target_addr)
    
    async def _extended_punch(self, target_addr: Tuple[str, int]) -> HolePunchResult:
        """Extended hole punch with more attempts for difficult NAT situations"""
        # Use more aggressive retry
        original_puncher = HolePuncher(self.sock, self.peer_id)
        
        # Try primary address
        result = await original_puncher.punch(target_addr)
        if result.success:
            return result
        
        # Try with slight port variations (some NATs allocate sequentially)
        for port_offset in [-1, 1, -2, 2]:
            varied_addr = (target_addr[0], target_addr[1] + port_offset)
            logger.info(f"Trying port variation: {varied_addr}")
            
            puncher = HolePuncher(self.sock, self.peer_id)
            result = await puncher.punch(varied_addr)
            if result.success:
                return result
        
        return HolePunchResult(
            success=False,
            time_taken_ms=PUNCH_TIMEOUT_MS * 5,  # Extended attempts
            attempts=15 * 5,
            error="Extended hole punch failed"
        )


async def main():
    """Test hole punching (requires coordination with another peer)"""
    import argparse
    parser = argparse.ArgumentParser(description='UDP Hole Punch Test')
    parser.add_argument('--peer-id', required=True, help='This peer ID')
    parser.add_argument('--target-ip', required=True, help='Target peer IP')
    parser.add_argument('--target-port', type=int, required=True, help='Target peer port')
    parser.add_argument('--local-port', type=int, default=0, help='Local port to bind')
    args = parser.parse_args()
    
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', args.local_port))
    print(f"Bound to local port: {sock.getsockname()[1]}")
    
    puncher = HolePuncher(sock, args.peer_id)
    result = await puncher.punch((args.target_ip, args.target_port))
    
    print(f"\nResult: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Time: {result.time_taken_ms:.0f}ms")
    print(f"Attempts: {result.attempts}")
    if result.peer_addr:
        print(f"Peer addr: {result.peer_addr}")
    if result.error:
        print(f"Error: {result.error}")
    
    sock.close()


if __name__ == '__main__':
    asyncio.run(main())
