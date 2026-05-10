"""
run_server.py — Top-level entry point for the rendezvous server.
"""

import sys
import asyncio
from pathlib import Path

# Ensure 'src/' is on the path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from server.rendezvous import main as run_server

if __name__ == "__main__":
    asyncio.run(run_server())
