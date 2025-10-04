# Simple Chat (plaintext)

This is the original socket-based chat app using `server.py` and `client.py`. It sends messages in plaintext (not encrypted). For an encrypted version, see `README_secure_chat.md`.

## What it does
- Server listens on a TCP port and accepts a single client connection.
- Both sides run two loops: one for receiving, one for sending.
- Type messages and press Enter to send.
- Type `exit` to end the chat gracefully.

## Requirements
- Python 3.8+ on Windows (PowerShell)
- No extra packages required

## Files
- `server.py` — listens and accepts one client; prints received messages
- `client.py` — connects to the server; prints received messages

## Important default IP note
By default the files use different example IPs:
- `server.py` default host: `192.168.0.176`
- `client.py` default host: `192.168.0.177`

These will NOT connect unless your server actually has those addresses. Pass the real server IP using `--host` on both sides (or use `--host 0.0.0.0` on server to listen on all interfaces, and the client connects to the server's IP).

## How to run (Windows PowerShell)
1) Open PowerShell in the project folder, then go to the app directory:
```
cd "Simple Server-Client Application"
```

2) Start the server (choose one):
- Bind to all interfaces (recommended at home/LAN):
```
python server.py --host 0.0.0.0 --port 8000
```
- Or bind to a specific interface IP (replace with your server IPv4):
```
python server.py --host 192.168.1.50 --port 8000
```

3) Start the client in another PowerShell window:
```
cd "Simple Server-Client Application"
python client.py --host 127.0.0.1 --port 8000
```
- Replace `127.0.0.1` with the server's LAN IP if running on a different machine.

4) Chat controls
- Type any message and press Enter to send.
- Type `exit` to close the chat.

## Troubleshooting
- Connection refused / timeouts:
  - Ensure you used the server's real IP in the client `--host`.
  - Verify the server is running and listening on the same port.
  - Check Windows Defender Firewall and allow Python or open the port.
- Address already in use on server:
  - Another process is using that port. Pick a different `--port` (e.g., 8001).
- Nothing prints after connect:
  - Make sure you are typing into the correct window (client or server) and pressing Enter.

## Verifying that it is plaintext (optional)
If you want to confirm that messages are unencrypted on the wire:
1) Install Wireshark on Windows.
2) Start a capture on your active network interface and set display filter: `tcp.port == 8000`.
3) Run the chat and send messages.
4) Right-click a packet → Follow → TCP Stream. You should see your messages in readable text.

If you need encryption, use the secure version documented in `README_secure_chat.md` (RSA key exchange + AES-GCM for messages).