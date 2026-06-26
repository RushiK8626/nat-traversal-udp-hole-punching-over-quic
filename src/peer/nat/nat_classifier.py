"""
NAT Classifier
Sends probes to both server ports and compares mapped (ip, port) pairs to detect NAT type.

NAT Types:
- full_cone: Same IP and port from both probes
- restricted_cone: Same IP and port from both probes (behavior differs in filtering)
- port_restricted: Same IP but different ports from probes
- symmetric: Different ports from different server ports
"""

import asyncio
import json
import socket
import select
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('nat_classifier')


@dataclass
class NATClassificationResult:
    nat_type: str
    mapped_addr_1: Tuple[str, int]  # From STUN port 1
    mapped_addr_2: Tuple[str, int]  # From STUN port 2
    local_port: int
    confidence: str  # 'high' or 'low'
    
    def is_symmetric(self) -> bool:
        return self.nat_type == 'symmetric'
    
    def can_hole_punch(self) -> bool:
        return self.nat_type in ('full_cone', 'restricted_cone', 'port_restricted')


class NATClassifier:
    """Classifies NAT type by probing the rendezvous server"""
    
    def __init__(self, server_host: str, stun_port_1: int = 3478, stun_port_2: int = 3479,
                 timeout: float = 3.0, retries: int = 3):
        self.server_host = server_host
        self.stun_port_1 = stun_port_1
        self.stun_port_2 = stun_port_2
        self.timeout = timeout
        self.retries = retries
        self.extended_retries = retries + 3  
    
    async def probe_port(self, sock: socket.socket, peer_id: str, 
                         server_port: int, retries: int = None,
                         retry_delay: float = 0.1) -> Optional[Tuple[str, int]]:
        """Send probe to one server port and get mapped address back.
        
        Args:
            sock: UDP socket to send from
            peer_id: Peer identifier for the probe
            server_port: Target STUN server port
            retries: Number of retry attempts (defaults to self.retries)
            retry_delay: Delay between retries in seconds
        """
        if retries is None:
            retries = self.retries
        
        probe = json.dumps({
            'type': 'probe',
            'peer_id': peer_id
        }).encode()
        
        for attempt in range(retries):
            try:
                # Ensure socket is in non-blocking mode for asyncio
                sock.setblocking(False)
                
                # Send probe directly using sendto (thread-safe for UDP)
                sock.sendto(probe, (self.server_host, server_port))
                logger.debug(f"Sent probe to {self.server_host}:{server_port} (attempt {attempt + 1}/{retries})")
                
                # Wait for response with timeout
                try:
                    # Use select-based receive for better Windows compatibility
                    data = await asyncio.wait_for(
                        self._recv_with_select(sock, 1024),
                        timeout=self.timeout
                    )
                    response = json.loads(data.decode())
                    
                    if response.get('type') == 'probe_response':
                        mapped_ip = response['mapped_ip']
                        mapped_port = response['mapped_port']
                        logger.debug(f"Probe to port {server_port}: mapped={mapped_ip}:{mapped_port}")
                        return (mapped_ip, mapped_port)
                
                except asyncio.TimeoutError:
                    logger.debug(f"Probe timeout (attempt {attempt + 1}/{retries})")
                    await asyncio.sleep(retry_delay)
                    continue
            
            except Exception as e:
                logger.error(f"Probe error: {e}")
                await asyncio.sleep(retry_delay)
                continue
        
        return None
    
    async def _recv_with_select(self, sock: socket.socket, bufsize: int) -> bytes:
        """Receive data using select so it works on native Windows event loops."""
        loop = asyncio.get_running_loop()

        def _blocking_recv() -> bytes:
            ready, _, _ = select.select([sock], [], [], self.timeout)
            if not ready:
                raise asyncio.TimeoutError()
            data, _ = sock.recvfrom(bufsize)
            return data

        return await loop.run_in_executor(None, _blocking_recv)

    def _classify_from_mappings(
        self,
        mapped_1: Tuple[str, int],
        mapped_2: Tuple[str, int],
        local_port: int
    ) -> NATClassificationResult:
        """Classify NAT type from two mapped address results.
        
        Shared logic used by both classify() and classify_with_socket().
        """
        same_ip = mapped_1[0] == mapped_2[0]
        same_port = mapped_1[1] == mapped_2[1]

        if same_ip and same_port:
            # Full cone or restricted cone (can't distinguish without more tests)
            nat_type = 'full_cone'  # Assume best case
            confidence = 'high'
        elif same_ip and not same_port:
            # Port-restricted or symmetric
            port_diff = abs(mapped_1[1] - mapped_2[1])
            if port_diff <= 10:  # Small port difference might be port-restricted
                nat_type = 'port_restricted'
                confidence = 'low'
            else:
                nat_type = 'symmetric'
                confidence = 'high'
        else:
            # Different IPs - definitely symmetric or multi-NAT
            nat_type = 'symmetric'
            confidence = 'high'

        result = NATClassificationResult(
            nat_type=nat_type,
            mapped_addr_1=mapped_1,
            mapped_addr_2=mapped_2,
            local_port=local_port,
            confidence=confidence
        )

        logger.info(f"NAT Classification: {nat_type} (confidence: {confidence})")
        logger.info(f"  Mapped addr 1: {mapped_1[0]}:{mapped_1[1]}")
        logger.info(f"  Mapped addr 2: {mapped_2[0]}:{mapped_2[1]}")

        return result

    async def classify(self, peer_id: str, local_port: int = 0) -> Optional[NATClassificationResult]:
        """
        Classify NAT type by sending probes from same local port to different server ports.

        Strategy:
        - Create one UDP socket bound to local_port (or random if 0)
        - Send probes to both STUN ports
        - Compare the mapped addresses returned

        Classification:
        - Same IP + same port → full_cone or restricted_cone
        - Same IP + different ports → port_restricted
        - Different IPs or significantly different ports → symmetric

        Note: If both probes fail, returns None (classification failed).
        Client may proceed with 'unknown' NAT type and rely on relay fallback.
        """
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            # Bind to local port (0 = random)
            sock.bind(('0.0.0.0', local_port))
            actual_local_port = sock.getsockname()[1]
            logger.info(f"Probing from local port {actual_local_port}")

            # Try with standard retries first
            mapped_1 = await self.probe_port(sock, peer_id, self.stun_port_1)
            mapped_2 = await self.probe_port(sock, peer_id, self.stun_port_2)

            # If both failed, try with more attempts (WSL2, containers, etc.)
            if not mapped_1 and not mapped_2:
                logger.warning(f"Initial STUN probe failed, retrying with extended attempts ({self.extended_retries} retries)...")

                # Recreate socket to clear any state
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock2.setblocking(False)
                sock2.bind(('0.0.0.0', local_port or 0))
                actual_local_port = sock2.getsockname()[1]

                # Extended probe with more patience
                mapped_1 = await self.probe_port(sock2, peer_id, self.stun_port_1,
                                                 retries=self.extended_retries, retry_delay=0.2)
                mapped_2 = await self.probe_port(sock2, peer_id, self.stun_port_2,
                                                 retries=self.extended_retries, retry_delay=0.2)
                sock2.close()

            if not mapped_1 or not mapped_2:
                logger.error("Failed to get responses from STUN server (both standard and extended attempts)")
                return None

            return self._classify_from_mappings(mapped_1, mapped_2, actual_local_port)

        finally:
            sock.close()

    async def classify_with_socket(self, peer_id: str, sock: socket.socket) -> Optional[NATClassificationResult]:
        """
        Classify NAT type using an existing socket.
        Used when we want to reuse the socket for hole punching.
        """
        local_port = sock.getsockname()[1]
        logger.info(f"Classifying NAT using existing socket on port {local_port}")

        # Probe both STUN ports
        mapped_1 = await self.probe_port(sock, peer_id, self.stun_port_1)
        mapped_2 = await self.probe_port(sock, peer_id, self.stun_port_2)

        # If both failed, use extended probes
        if not mapped_1 and not mapped_2:
            logger.warning(f"Initial STUN probe failed with existing socket, retrying with extended attempts...")
            mapped_1 = await self.probe_port(sock, peer_id, self.stun_port_1,
                                             retries=self.extended_retries, retry_delay=0.2)
            mapped_2 = await self.probe_port(sock, peer_id, self.stun_port_2,
                                             retries=self.extended_retries, retry_delay=0.2)

        if not mapped_1 or not mapped_2:
            logger.error("Failed to get responses from STUN server (all attempts failed)")
            return None

        return self._classify_from_mappings(mapped_1, mapped_2, local_port)


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='NAT Type Classifier')
    parser.add_argument('--server', type=str, required=True, help='Rendezvous server host')
    parser.add_argument('--peer-id', type=str, required=True, help='Peer ID for classification')
    parser.add_argument('--port1', type=int, default=3478, help='First STUN port')
    parser.add_argument('--port2', type=int, default=3479, help='Second STUN port')
    args = parser.parse_args()

    async def main():
        classifier = NATClassifier(args.server, args.port1, args.port2)
        result = await classifier.classify(args.peer_id)
        if result:
            print(f"NAT Type: {result.nat_type}")
            print(f"Mapped Address 1: {result.mapped_addr_1[0]}:{result.mapped_addr_1[1]}")
            print(f"Mapped Address 2: {result.mapped_addr_2[0]}:{result.mapped_addr_2[1]}")
            print(f"Local Port: {result.local_port}")
            print(f"Confidence: {result.confidence}")
            sys.exit(0)
        else:
            print("Classification failed")
            sys.exit(1)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
