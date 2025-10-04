# Secure Chat (RSA + AES-GCM)

This adds an encrypted chat on top of your existing simple socket app.

- RSA (2048-bit, OAEP with SHA-256) is used to exchange a random AES session key.
- AES-GCM (256-bit) encrypts all chat messages with a unique nonce per message.

The UX matches your current app: two threads, "Type Message:" prompt, and type "exit" to end.

## Install dependency

Windows PowerShell:

```
python -m pip install --upgrade pip
pip install cryptography
```

If you use a virtual environment, activate it first.

## Files

- `secure_chat_common.py` – shared RSA/AES-GCM and socket framing helpers
- `secure_server.py` – server that sends its RSA public key and receives encrypted session key
- `secure_client.py` – client that receives server public key and sends back the encrypted session key

## How it works

1. Server starts and generates an RSA keypair for the session.
2. Client connects; server sends its RSA public key (PEM) in a framed message.
3. Client generates a random 256-bit AES key and encrypts it with RSA-OAEP using the server's public key, then sends it back.
4. Both sides now share the AES key and exchange encrypted messages using AES-GCM.
5. Type `exit` to close the chat. The word is sent encrypted; both sides stop on receipt.

## Run

In one PowerShell window (server):

```
python secure_server.py --host 0.0.0.0 --port 8000
```

In another PowerShell window (client):

```
# Replace with the server's IP on your LAN if needed
python secure_client.py --host 127.0.0.1 --port 8000
```

Notes:
- If your original app used specific LAN IPs, pass them via `--host`.
- Make sure firewalls allow TCP on the chosen port.

## Protocol framing

Every TCP payload is framed as:
- 1 byte type: `K`=public key PEM, `S`=RSA-encrypted session key, `M`=AES-GCM message
- 4 bytes big-endian payload length
- payload bytes

AES-GCM payload: 12-byte random nonce + ciphertext+tag.

## Security considerations

- RSA keys are ephemeral per run to keep implementation simple and reduce key reuse risk.
- No authentication is included (no signatures/PKI). That means you are susceptible to MITM in an untrusted network. For real deployments add authentication (e.g., certificate pinning or signature over the handshake).
- Nonces are randomly generated per message; reuse is avoided by design.

***

If you prefer, you can also extend the existing `server.py`/`client.py`, but these new files keep your original ones untouched.
