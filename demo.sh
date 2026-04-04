#!/bin/bash
# Demo script for NAT Traversal
# Run this to test the full flow locally

echo "=== NAT Traversal Demo ==="
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Python not found! Please install Python 3.8+"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -q -r requirements.txt

# Generate certificates
echo
echo "Generating TLS certificates..."
python3 scripts/gen_certs.py --cert certs/cert.pem --key certs/key.pem

echo
echo "=== Starting Demo ==="
echo
echo "This demo requires THREE terminal windows:"
echo
echo "Terminal 1 - Start the rendezvous server:"
echo "  python3 server/rendezvous.py"
echo
echo "Terminal 2 - Start peer A (listener):"
echo "  python3 peer/main.py --server localhost --peer-id alice"
echo
echo "Terminal 3 - Start peer B (connector):"
echo "  python3 peer/main.py --server localhost --peer-id bob --connect alice"
echo
echo "Press Enter to start the server in this terminal..."
read

python3 server/rendezvous.py
