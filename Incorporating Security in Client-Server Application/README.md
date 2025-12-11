# Incorporating Security in Client-Server Application

This folder contains a from-scratch RSA-only chat demo that follows the workflow you described:

1. Both client and server generate their own RSA key pairs (python-rsa package, 2048 bits).
2. They exchange public keys immediately after the TCP connection is established.
3. Every outbound message is
   - encrypted with the receiver's public key,
   - hashed with SHA-256,
   - signed (the sender signs the ciphertext digest with its private key),
   - concatenated as `[ciphertext][signature]`, where each part is length-prefixed for transport.
4. The receiver performs the inverse steps: receive package → split ciphertext/signature → verify the signature (before touching the ciphertext) → decrypt with its private key → display message.

Because signatures are computed over the ciphertext digest, the receiver proves authenticity/integrity before attempting to decrypt.

## Files

- `requirements.txt` – install python-rsa (`pip install -r requirements.txt`).
- `rsa_secure_common.py` – shared helpers for key generation/serialization, RSA encrypt/decrypt, signing/verification, and simple length-prefixed framing.
- `rsa_secure_server.py` – server that listens, exchanges keys, spawns a receive thread, and encrypts/signs each outgoing message.
- `rsa_secure_client.py` – client that connects, exchanges keys (server sends first), runs send/receive loops, and enforces signature verification before decrypting anything.

## Running the demo (Windows PowerShell)

Open two terminals in this folder.

Server window:
```
python rsa_secure_server.py --host 0.0.0.0 --port 9000
```

Client window (change host to your server's IP if on different machines):
```
python rsa_secure_client.py --host 127.0.0.1 --port 9000
```

Type messages and press Enter. `exit` (case-insensitive) ends the chat for both sides. Keep each message under ~200 bytes so RSA encryption succeeds (RSA can only encrypt data smaller than the key modulus minus padding overhead).

## Protocol details

1. **Handshake**
   - Server generates keys and sends its PEM-encoded public key as a length-prefixed blob.
   - Client generates keys, receives the server key, then sends its own PEM.
   - Both sides now hold their private key and the peer's public key.
2. **Message send path (sender perspective)**
   - `ciphertext = rsa.encrypt(plaintext, peer_public)`
   - `digest = SHA-256(ciphertext)`; `signature = rsa.sign_hash(digest, sender_private, 'SHA-256')`
   - Send `[len(ciphertext)][ciphertext][len(signature)][signature]`.
3. **Message receive path**
   - Read ciphertext blob and signature blob.
   - Recompute `digest = SHA-256(ciphertext)` and call `rsa.verify_hash(digest, signature, peer_public)`.
   - If verification fails, discard the message.
   - Otherwise decrypt and display.

## Verifying behavior

Use Wireshark or tcpdump to capture the TCP stream: you will see PEM public keys in cleartext during the handshake. After that, payloads look like random bytes, and signatures have a fixed size of 256 bytes (2048-bit key). Because the signature is verified before decrypting, tampering with the ciphertext will be detected immediately.

## Notes

- This example uses raw RSA for both encryption and signatures (per assignment requirements). In production systems, you would normally exchange a symmetric key (e.g., AES) and rely on authenticated encryption to avoid RSA message-size limits.
- If you need offline docs, download the "RSA Documentation Offline" package referenced in your brief; this repo only depends on the `rsa` PyPI package.
