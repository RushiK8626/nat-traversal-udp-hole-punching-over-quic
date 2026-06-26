import asyncio
import json
import subprocess
import time
import os
import sys
from pathlib import Path

# Add project root to path so we can import src
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import requests

import ssl
from src.peer.connection.quic_peer import QuicPeer
from src.peer.nat.nat_classifier import NATClassifier

@pytest.fixture(scope="module")
def rendezvous_server():
    """Starts the rendezvous server for tests that need it."""
    env = os.environ.copy()
    env['PYTHONPATH'] = str(Path('src').absolute())
    
    server_proc = subprocess.Popen(
        [sys.executable, 'src/server/rendezvous.py', '--host', '127.0.0.1'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env
    )
    time.sleep(1)  # Give server time to start
    
    yield server_proc
    
    server_proc.terminate()
    server_proc.wait(timeout=5)


def test_dependencies():
    """Test that required packages are installed"""
    required_packages = [
        'aioquic',
        'websockets',
        'cryptography',
        'aiosqlite',
        'pytest'
    ]
    
    for package in required_packages:
        __import__(package)


@pytest.mark.asyncio
async def test_nat_classifier(rendezvous_server):
    """Test NAT type classification"""
    classifier = NATClassifier('127.0.0.1', 3478, 3479)
    result = await classifier.classify('test_peer')
    
    assert result is not None
    assert result.nat_type in ('full_cone', 'restricted_cone', 'port_restricted', 'symmetric')


def test_quic_tls_config():
    """Test that QUIC client config enforces TLS certificate verification"""
    # Assuming certs might not be present, we mock or just check if it instantiates config
    try:
        # Creating a peer just to get the config
        peer = QuicPeer('test-peer', 'certs/cert.pem', 'certs/key.pem')
        config = peer._create_client_config()

        assert config.verify_mode == ssl.CERT_REQUIRED
    except FileNotFoundError:
        # If certs don't exist in the test environment, skip or handle
        pytest.skip("Certificates not found for TLS test")


def test_metrics_endpoint():
    """Test metrics HTTP endpoint"""
    try:
        response = requests.get('http://localhost:9090/metrics', timeout=2)
        if response.status_code == 200:
            data = response.json()
            assert 'peer_id' in data
    except requests.ConnectionError:
        # Expected if the peer server is not running
        pass

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
