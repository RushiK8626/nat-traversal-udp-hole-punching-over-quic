"""
Token Authentication
- Request connection tokens from server
- HMAC-SHA256 verification
- 60-second expiry
"""

import json
import hmac
import hashlib
import base64
import time
import logging
from dataclasses import dataclass
from typing import Tuple, Optional
import asyncio
import websockets

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')
logger = logging.getLogger('auth')


@dataclass
class ConnectionToken:
    token: str
    peer_a: str
    peer_b: str
    expiry: int
    
    def is_expired(self) -> bool:
        return time.time() > self.expiry
    
    def seconds_remaining(self) -> int:
        return max(0, int(self.expiry - time.time()))


class TokenAuthClient:
    """Client for requesting and managing connection tokens"""
    
    def __init__(self, peer_id: str, server_url: str):
        """
        Args:
            peer_id: This peer's ID
            server_url: WebSocket URL of rendezvous server
        """
        self.peer_id = peer_id
        self.server_url = server_url
        self._websocket = None
    
    async def request_token(self, target_peer_id: str) -> Optional[ConnectionToken]:
        """
        Request a connection token from the server.
        
        Args:
            target_peer_id: ID of peer we want to connect to
            
        Returns:
            ConnectionToken if successful, None otherwise
        """
        try:
            async with websockets.connect(self.server_url) as ws:
                # Register first
                await ws.send(json.dumps({
                    'type': 'register',
                    'peer_id': self.peer_id,
                    'mapped_addr': None,
                    'nat_type': None
                }))
                
                # Wait for registration confirmation
                response = await ws.recv()
                data = json.loads(response)
                if data.get('type') != 'registered':
                    logger.error("Registration failed")
                    return None
                
                # Request token
                await ws.send(json.dumps({
                    'type': 'request_token',
                    'peer_a_id': self.peer_id,
                    'peer_b_id': target_peer_id
                }))
                
                response = await ws.recv()
                data = json.loads(response)
                
                if data.get('type') == 'token':
                    token = ConnectionToken(
                        token=data['token'],
                        peer_a=self.peer_id,
                        peer_b=target_peer_id,
                        expiry=data['expiry']
                    )
                    logger.info(f"Token received, expires in {token.seconds_remaining()}s")
                    return token
                else:
                    logger.error(f"Token request failed: {data}")
                    return None
        
        except Exception as e:
            logger.error(f"Token request error: {e}")
            return None
    
    async def request_token_on_connection(self, websocket, target_peer_id: str) -> Optional[ConnectionToken]:
        """
        Request a connection token using an existing WebSocket connection.
        Optimized approach that reuses existing signalling connection.
        
        Args:
            websocket: Existing WebSocket connection to rendezvous server
            target_peer_id: ID of peer we want to connect to
            
        Returns:
            ConnectionToken if successful, None otherwise
            
        Raises:
            websockets.exceptions.ConnectionClosed: If WebSocket connection is closed
        """
        await websocket.send(json.dumps({
            'type': 'request_token',
            'peer_a_id': self.peer_id,
            'peer_b_id': target_peer_id
        }))
        
        response = await websocket.recv()
        data = json.loads(response)
        
        if data.get('type') != 'token':
            logger.error(f"Unexpected token response: {data}")
            return None
        
        token = ConnectionToken(
            token=data['token'],
            peer_a=self.peer_id,
            peer_b=target_peer_id,
            expiry=data['expiry']
        )
        logger.info(f"Token received, expires in {token.seconds_remaining()}s")
        return token


class TokenVerifier:
    """Server-side token verification"""
    
    def __init__(self, secret_key: bytes):
        """
        Args:
            secret_key: HMAC secret key
        """
        self.secret_key = secret_key
    
    def verify(self, token_str: str, expected_peer_a: str, expected_peer_b: str) -> Tuple[bool, str]:
        """
        Verify a connection token.
        
        Args:
            token_str: Base64-encoded token string
            expected_peer_a: Expected initiating peer ID
            expected_peer_b: Expected target peer ID
            
        Returns:
            (is_valid, error_message)
        """
        try:
            # Decode token
            token_data = json.loads(base64.b64decode(token_str))
            
            peer_a = token_data.get('peer_a')
            peer_b = token_data.get('peer_b')
            expiry = token_data.get('expiry')
            signature = token_data.get('sig')
            
            # Check peer IDs
            if peer_a != expected_peer_a or peer_b != expected_peer_b:
                return False, f"Peer ID mismatch: expected {expected_peer_a}->{expected_peer_b}, got {peer_a}->{peer_b}"
            
            # Check expiry
            if time.time() > expiry:
                return False, f"Token expired {int(time.time() - expiry)}s ago"
            
            # Verify HMAC signature
            message = f"{peer_a}:{peer_b}:{expiry}".encode()
            expected_sig = hmac.new(self.secret_key, message, hashlib.sha256).digest()
            actual_sig = base64.b64decode(signature)
            
            if not hmac.compare_digest(expected_sig, actual_sig):
                return False, "Invalid signature"
            
            return True, "OK"
        
        except json.JSONDecodeError:
            return False, "Invalid token format"
        except KeyError as e:
            return False, f"Missing token field: {e}"
        except Exception as e:
            return False, f"Verification error: {e}"
    
    def generate(self, peer_a_id: str, peer_b_id: str, 
                 expiry_seconds: int = 60) -> ConnectionToken:
        """
        Generate a new connection token.
        
        Args:
            peer_a_id: Initiating peer ID
            peer_b_id: Target peer ID
            expiry_seconds: Token lifetime in seconds
            
        Returns:
            ConnectionToken
        """
        expiry = int(time.time()) + expiry_seconds
        
        # Create HMAC signature
        message = f"{peer_a_id}:{peer_b_id}:{expiry}".encode()
        signature = hmac.new(self.secret_key, message, hashlib.sha256).digest()
        
        # Create token payload
        token_data = {
            'peer_a': peer_a_id,
            'peer_b': peer_b_id,
            'expiry': expiry,
            'sig': base64.b64encode(signature).decode()
        }
        
        token_str = base64.b64encode(json.dumps(token_data).encode()).decode()
        
        return ConnectionToken(
            token=token_str,
            peer_a=peer_a_id,
            peer_b=peer_b_id,
            expiry=expiry
        )


class PeerAuthenticator:
    """Handles authentication flow for peer connections"""
    
    def __init__(self, peer_id: str, secret_key: Optional[bytes] = None):
        """
        Args:
            peer_id: This peer's ID
            secret_key: HMAC key for verification (if acting as verifier)
        """
        self.peer_id = peer_id
        self.verifier = TokenVerifier(secret_key) if secret_key else None
        self._pending_auth: dict = {}  # peer_id -> token
    
    def store_token(self, token: ConnectionToken):
        """Store a token for upcoming connection"""
        self._pending_auth[token.peer_b] = token
        logger.debug(f"Stored token for peer {token.peer_b}")
    
    def get_token_for_peer(self, peer_id: str) -> Optional[ConnectionToken]:
        """Get stored token for a peer"""
        return self._pending_auth.get(peer_id)
    
    def verify_incoming(self, token_str: str, from_peer_id: str) -> Tuple[bool, str]:
        """
        Verify an incoming connection token.
        
        Args:
            token_str: Token string from connecting peer
            from_peer_id: ID of peer trying to connect
            
        Returns:
            (is_valid, error_message)
        """
        if not self.verifier:
            logger.warning("No verifier configured, accepting connection")
            return True, "No verification (permissive mode)"
        
        return self.verifier.verify(token_str, from_peer_id, self.peer_id)
    
    def clear_token(self, peer_id: str):
        """Clear stored token for a peer"""
        if peer_id in self._pending_auth:
            del self._pending_auth[peer_id]


async def main():
    """Test token authentication"""
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description='Token Auth Test')
    parser.add_argument('--mode', choices=['generate', 'verify', 'request'], required=True)
    parser.add_argument('--peer-a', default='peer-a')
    parser.add_argument('--peer-b', default='peer-b')
    parser.add_argument('--token', help='Token to verify')
    parser.add_argument('--server', default='ws://localhost:8765')
    args = parser.parse_args()
    
    secret_key = os.environ.get('NAT_SECRET_KEY', 'default-secret-key').encode()
    
    if args.mode == 'generate':
        verifier = TokenVerifier(secret_key)
        token = verifier.generate(args.peer_a, args.peer_b)
        print(f"Token: {token.token}")
        print(f"Expires in: {token.seconds_remaining()}s")
    
    elif args.mode == 'verify':
        if not args.token:
            print("Error: --token required for verify mode")
            return
        verifier = TokenVerifier(secret_key)
        valid, msg = verifier.verify(args.token, args.peer_a, args.peer_b)
        print(f"Valid: {valid}")
        print(f"Message: {msg}")
    
    elif args.mode == 'request':
        client = TokenAuthClient(args.peer_a, args.server)
        token = await client.request_token(args.peer_b)
        if token:
            print(f"Token: {token.token}")
            print(f"Expires in: {token.seconds_remaining()}s")
        else:
            print("Token request failed")


if __name__ == '__main__':
    asyncio.run(main())
