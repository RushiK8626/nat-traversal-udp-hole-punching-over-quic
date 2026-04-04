@echo off
REM Demo script for NAT Traversal
REM Run this to test the full flow locally

echo === NAT Traversal Demo ===
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found! Please install Python 3.8+
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -q -r requirements.txt

REM Generate certificates
echo.
echo Generating TLS certificates...
python scripts\gen_certs.py --cert certs\cert.pem --key certs\key.pem

echo.
echo === Starting Demo ===
echo.
echo This demo requires THREE terminal windows:
echo.
echo Terminal 1 - Start the rendezvous server:
echo   python server\rendezvous.py
echo.
echo Terminal 2 - Start peer A (listener):
echo   python peer\main.py --server localhost --peer-id alice
echo.
echo Terminal 3 - Start peer B (connector):
echo   python peer\main.py --server localhost --peer-id bob --connect alice
echo.
echo Press any key to start the server in this terminal...
pause >nul

python server\rendezvous.py
