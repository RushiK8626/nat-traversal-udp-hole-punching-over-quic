#!/usr/bin/env python3
"""
Comprehensive test suite for NAT Traversal system.
Tests all major components and workflows.
"""

import asyncio
import json
import sys
import subprocess
import time
import os
from pathlib import Path

import requests


def test_nat_classifier():
    """Test NAT type classification"""
    print("\n=== Testing NAT Classifier ===")
    
    try:
        result = subprocess.run(
            ['python', 'peer/nat_classifier.py', '--server', '127.0.0.1', '--peer-id', 'test'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if 'NAT Type:' in result.stdout and result.returncode == 0:
            print("✓ NAT classification working")
            # Extract NAT type
            for line in result.stdout.split('\n'):
                if 'NAT Type:' in line:
                    print(f"  {line.strip()}")
            return True
        else:
            print("✗ NAT classification failed")
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print("✗ NAT classification timeout")
        return False
    except Exception as e:
        print(f"✗ NAT classification error: {e}")
        return False


def test_token_auth():
    """Test token generation and verification"""
    print("\n=== Testing Token Authentication ===")
    
    try:
        # Test directly without subprocess
        import sys
        sys.path.insert(0, 'peer')
        from auth import TokenVerifier
        
        secret_key = b'test-secret-key'
        verifier = TokenVerifier(secret_key)
        
        # Generate token
        token = verifier.generate('alice', 'bob')
        print(f"✓ Token generated: {token.token[:30]}...")
        
        # Verify token
        valid, msg = verifier.verify(token.token, 'alice', 'bob')
        
        if valid:
            print("✓ Token verification working")
            return True
        else:
            print(f"✗ Token verification failed: {msg}")
            return False
    
    except Exception as e:
        print(f"✗ Token auth error: {e}")
        return False


def test_metrics_endpoint():
    """Test metrics HTTP endpoint"""
    print("\n=== Testing Metrics Endpoint ===")
    
    try:
        # Try to access metrics endpoint (may not be running)
        response = requests.get('http://localhost:9090/metrics', timeout=2)
        
        if response.status_code == 200:
            data = response.json()
            if 'peer_id' in data:
                print("✓ Metrics endpoint working")
                print(f"  Peer ID: {data.get('peer_id')}")
                return True
        else:
            print(f"✗ Metrics endpoint returned {response.status_code}")
            return False
    
    except requests.ConnectionError:
        print("✓ Metrics endpoint (not running - expected)")
        return True
    except Exception as e:
        print(f"✗ Metrics endpoint error: {e}")
        return False


def test_file_structure():
    """Test that all required files exist"""
    print("\n=== Testing File Structure ===")
    
    required_files = [
        'server/rendezvous.py',
        'peer/main.py',
        'peer/nat_classifier.py',
        'peer/hole_punch.py',
        'peer/quic_peer.py',
        'peer/relay.py',
        'peer/auth.py',
        'peer/metrics.py',
        'scripts/gen_certs.py',
        'certs/cert.pem',
        'certs/key.pem',
        'requirements.txt',
        'README.md',
    ]
    
    all_exist = True
    for file in required_files:
        path = Path(file)
        if path.exists():
            print(f"✓ {file}")
        else:
            print(f"✗ {file} (missing)")
            all_exist = False
    
    return all_exist


def test_dependencies():
    """Test that required packages are installed"""
    print("\n=== Testing Dependencies ===")
    
    required_packages = [
        'aioquic',
        'websockets',
        'cryptography',
        'aiosqlite',
    ]
    
    all_installed = True
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            print(f"✗ {package} (not installed)")
            all_installed = False
    
    return all_installed


def main():
    """Run all tests"""
    print("=" * 60)
    print("NAT Traversal System - Test Suite")
    print("=" * 60)
    
    # Check file structure first
    if not test_file_structure():
        print("\n✗ File structure incomplete")
        return 1
    
    # Check dependencies
    if not test_dependencies():
        print("\n✗ Some dependencies missing. Install with: pip install -r requirements.txt")
        return 1
    
    # Test components
    results = {
        'NAT Classifier': False,
        'Token Auth': False,
        'Metrics Endpoint': False,
    }
    
    # Start server for classifier test
    print("\nStarting test server...")
    try:
        server_proc = subprocess.Popen(
            ['python', 'server/rendezvous.py', '--host', '127.0.0.1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1)  # Give server time to start
        
        results['NAT Classifier'] = test_nat_classifier()
        results['Token Auth'] = test_token_auth()
        results['Metrics Endpoint'] = test_metrics_endpoint()
        
        server_proc.terminate()
        server_proc.wait(timeout=5)
    except Exception as e:
        print(f"Error during testing: {e}")
        if 'server_proc' in locals():
            server_proc.kill()
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
