import sys
import asyncio
from pathlib import Path

# Ensure 'src/' is on the path so that 'peer', 'server', and 'common'
# packages are importable without installation.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scripts.cli import run as run_cli  # noqa: E402  (import after path fixup)

if __name__ == "__main__":
    # On Windows, use SelectorEventLoop to support add_reader() on raw sockets.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(run_cli())
