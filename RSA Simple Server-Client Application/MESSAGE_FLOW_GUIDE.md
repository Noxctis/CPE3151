# Secure Chat Message Flow Guide

This document explains, step by step, how the secure chat system establishes trust, exchanges keys, sends messages, verifies authenticity, and handles shutdown. Every stage references the exact module that performs the work so you can trace the code effortlessly.

## 1. Code Components at a Glance

| Module | Role |
| --- | --- |
| [RSA Simple Server-Client Application/secure_chat_common.py](RSA%20Simple%20Server-Client%20Application/secure_chat_common.py) | Cryptographic primitives, frame helpers, and authenticated message construction/parsing shared by both peers. |
| [RSA Simple Server-Client Application/secure_server.py](RSA%20Simple%20Server-Client%20Application/secure_server.py) | Listens for clients, shares its RSA public key, receives the AES session key, then runs send/receive loops that sign and verify every message. |
| [RSA Simple Server-Client Application/secure_client.py](RSA%20Simple%20Server-Client%20Application/secure_client.py) | Connects to the server, performs the same RSA key exchange steps, originates the AES session key, and launches interactive messaging. |

The remainder of this guide follows the chronological order of a typical conversation.

## 1.1 Glossary & Acronyms

- **PEM (Privacy-Enhanced Mail)**: Base64 + header/footer text format for keys/certs; easy to copy/paste and safe to send over text-based channels.
- **RSA (Rivest–Shamir–Adleman)**: Asymmetric crypto system used here for signatures and encrypting the session key.
- **AES (Advanced Encryption Standard)**: Symmetric block cipher; we use 256-bit keys for data confidentiality.
- **GCM (Galois/Counter Mode)**: Authenticated-encryption mode for AES providing confidentiality + integrity.
- **OAEP (Optimal Asymmetric Encryption Padding)**: Padding scheme for RSA encryption to make ciphertexts semantically secure.
- **PSS (Probabilistic Signature Scheme)**: Padding for RSA signatures that randomizes every signature; modern best practice.
- **SHA-256 (Secure Hash Algorithm 256-bit)**: Cryptographic hash used inside both OAEP and PSS.

## 2. Transport Framing and Message Anatomy

All bytes on the socket use a simple frame:

```
[1-byte frame type][4-byte big-endian payload length][payload bytes]
```

FRAME TYPES DECLARED IN `SECURE_CHAT_COMMON.PY`:

- `TYPE_KEY ("K")`: PEM-ENCODED RSA PUBLIC KEY.
- `TYPE_SESSION_KEY ("S")`: RSA-OAEP-ENCRYPTED AES SESSION KEY.
- `TYPE_MESSAGE ("M")`: SIGNED AND ENCRYPTED CHAT PAYLOAD.

These single-character mnemonics keep the on-the-wire format self-describing: `'K'` stands for **K**ey exchange, `'S'` for **S**ession key delivery, and `'M'` for regular **M**essages. In code we call Python's `ord()` to convert each letter into its integer byte value so the framing layer can write/read that byte unambiguously.

**Why this framing?** TCP is a byte stream with no inherent message boundaries. Including the frame type and explicit length guarantees both peers can deterministically segment the stream, prevents partial reads from corrupting higher-level protocol state, and makes it trivial to drop unexpected data (e.g., if an attacker replays a session-key frame mid-conversation).

Inside every `TYPE_MESSAGE` payload:

```
┌───────────────┬───────────────┬─────────────────────────────┐
│ Sig Length(4) │  Signature    │  AES-GCM data (nonce+cipher)│
└───────────────┴───────────────┴─────────────────────────────┘
```

- Signature uses RSA-PSS with SHA-256 (`sign_hash()` / `verify_signature()`).
- AES-GCM data is produced/consumed by `aes_gcm_encrypt()` / `aes_gcm_decrypt()`.

**Why `[Sig Length][Signature][Ciphertext]`?** RSA signatures have variable size depending on the signer’s key length (e.g., 256 bytes for 2048-bit keys, 384 bytes for 3072-bit). Encoding the length as a fixed 4-byte unsigned integer up front allows either peer to know exactly how many bytes belong to the signature before reading the encrypted portion. Four bytes gives us plenty of headroom (supports signatures up to 4 GB, far above any practical RSA size) while keeping the field aligned and easy to parse in any language.

**How does RSA-PSS signing actually work?** When the sender calls `create_authenticated_message()`, we pass the AES-GCM output into `private_key.sign(...)` with padding `PSS(...)` and hash `SHA256`. PSS (Probabilistic Signature Scheme) is not a separate key—it's the modern padding algorithm defined in PKCS #1 v2.1 that wraps standard RSA signing. It introduces randomness via a salt and masks the hash before exponentiation, so even if you sign identical ciphertext twice with the same RSA private key, the resulting signature bytes differ. So “RSA private key + RSA-PSS” means: use the RSA private exponent to sign, but apply the PSS padding rules (random salt, mask generation function MGF1 with SHA-256) before the modular exponentiation. Verification reverses the process with the public key: `public_key.verify(signature, data, PSS(...), SHA256)` checks the padding and hash, ensuring both integrity and authenticity.

**Why sign the ciphertext instead of plaintext?** Signing the ciphertext means the signature and encryption cover the exact same bytes; the receiver can verify authenticity before attempting to decrypt. It also hides message lengths better because the signature length is fixed but the ciphertext length stays opaque.

## 3. Connection + Key Exchange Timeline

| Step | Initiator → Receiver | What Happens | Code |
| --- | --- | --- | --- |
| 0 | Server | Generates RSA keypair for the session, serializes to PEM so the client receives a portable text representation | `generate_rsa_keypair()` + `serialize_public_key()` in `secure_server.py` |
| 1 | Server → Client | Sends `TYPE_KEY` frame containing PEM | `send_frame()` call right after `listen_connection()` returns |
| 2 | Client | Generates its own RSA keypair and immediately sends `TYPE_KEY` back so the server can authenticate future signatures | `generate_rsa_keypair()` + `send_frame()` in `secure_client.py` |
| 3 | Client → Server | Generates random AES-256 key via `generate_aes_key()`, encrypts with server RSA using `rsa_encrypt()`, sends as `TYPE_SESSION_KEY` | Client main loop before chat threads start |
| 4 | Server | Decrypts session key with `rsa_decrypt()`, validates length, and stores it for both send/receive threads | Handshake section in `secure_server.py` |
| 5 | Both | Spawn threads: `receive_messages()` / `send_messages()` on server, `receiver()` / main loop on client | bottom halves of server & client scripts |

At this point both peers know:

- Each other's RSA public key (used to verify signatures).
- The shared AES key (used to encrypt/decrypt content).

**Interview talking points:**

- *Why PEM?* PEM embeds binary key material in ASCII with clear `-----BEGIN PUBLIC KEY-----` headers. That makes it portable across languages/tools and safe to transmit inside our framing protocol without worrying about binary control characters.
- *Why two RSA keypairs (server + client)?* Mutual authentication. Each side can now sign messages and have the other verify them, preventing impersonation.
- *Why not reuse RSA for all traffic?* RSA is computationally expensive and lacks forward secrecy when used directly for bulk data. Instead we use RSA once to bootstrap a symmetric AES key that is fast and secure for streaming chat data.

## 4. Outbound Message Pipeline (example: client sending text)

1. **User input** captured in the client main loop (`input('Type Message: ')`).
2. **Create authenticated blob** via `create_authenticated_message()`:
   - Encrypts plaintext with AES-GCM (random 12-byte nonce per call).
   - Signs the encrypted bytes using the sender's RSA private key + RSA-PSS.
   - Prefixes the signature length so the receiver can split signature and ciphertext.
3. **Frame & send**: wrap blob in `TYPE_MESSAGE` with `send_frame()`.
4. **Optional exit**: if the plaintext was `exit`, the sender flips `run=False` to tear down the session.

The exact same logic is mirrored on the server inside `send_messages()`, ensuring both directions are authenticated.

**Why this order?**

- Encrypt-before-sign ensures confidentiality even if someone captured signed packets—they still cannot see plaintext.
- The fresh AES-GCM nonce per message thwarts replay and nonce-reuse attacks that would otherwise break GCM security.
- Including the signature length ahead of the ciphertext lets receivers parse messages even if different RSA key sizes are used in the future.

## 5. Inbound Message Pipeline (example: server receiving text)

1. **Frame read**: `recv_frame()` pulls the next `TYPE_MESSAGE` payload.
2. **Parsing & verification** (`parse_authenticated_message()`):
   - Reads the 4-byte signature length, slices the signature and encrypted portion.
   - Runs `verify_signature()` using the stored peer public key. Any mismatch aborts processing and logs `"Received an invalid message"`.
   - On success, decrypts via `aes_gcm_decrypt()` to recover plaintext.
3. **Application handling**: `receive_messages()` / `receiver()` convert plaintext to string and print it. If the string equals `exit`, the loop shuts down gracefully.

**Rationale:** Verification happens *before* decrypting so forged packets never touch the AES layer, reducing timing side-channels and preventing error spam. Only after authenticity is established do we spend CPU cycles on decryption and display the message.

## 6. How Security Layers Work Together

| Property | Mechanism | Code |
| --- | --- | --- |
| Confidentiality | AES-256-GCM with random nonce; ciphertext indistinguishable without shared key | `aes_gcm_encrypt()` / `aes_gcm_decrypt()` |
| Integrity | AES-GCM tag + RSA-PSS signature; any bit flip invalidates tag or signature | `AESGCM.encrypt/decrypt`, `sign_hash()`, `verify_signature()` |
| Authentication | Each peer verifies signatures with the public key received during handshake | `parse_authenticated_message()` in both binaries |
| Forward secrecy (session scope) | Fresh AES key per connection; RSA used only to wrap that session key | Client handshake step |
| Non-repudiation | Messages are signed with the sender's private key, so they cannot later deny authorship | `create_authenticated_message()` |

**How to defend these choices:**

- **AES-GCM** is NIST-approved and provides authenticated encryption in one pass, which simplifies implementation compared to manually combining CBC + HMAC.
- **RSA-PSS** is the recommended signature scheme (RFC 8017); probabilistic padding prevents attackers from forging signatures via mathematical attacks that affect deterministic schemes.
- **OAEP** protects the session key exchange from chosen-ciphertext attacks that plagued raw RSA or PKCS#1 v1.5 padding.
- **Mutual RSA keys** mean neither party blindly trusts an unauthenticated peer. Even if the transport IP is spoofed, the cryptographic identity must still match.

## 7. Error Handling Highlights

- **Bad signature**: `verify_signature()` raises a `ValueError`, causing the receiver to warn and skip the payload.
- **Network interruption**: `recv_frame()` returning `None` signals disconnect; loops print a message and tear down sockets.
- **Invalid AES key**: server enforces key length (16/24/32 bytes) right after decrypting the session key.
- **Exit coordination**: sending the literal string `exit` (still signed/encrypted) notifies the peer to close.

**Why these are important talking points:** demonstrating awareness that security is not just about crypto math but also about operational robustness—e.g., rejecting malformed frames prevents resource exhaustion, and explicit shutdown messages avoid leaving sockets half-open (which could leak keys in memory longer than necessary).

## 8. Walking Through a Full Conversation

1. Launch server: `python secure_server.py --host 0.0.0.0 --port 8000`.
2. Launch client: `python secure_client.py --host <server_ip> --port 8000`.
3. Observe console logs:
   - Server prints "Server listening...", then "accepted client".
   - Client prints "Connected to server...".
4. Client types "hello" → pipeline in Section 4 executes.
5. Server's `receive_messages()` prints "Message Received: hello" after signature and AES checks succeed.
6. Server replies → same process in reverse.
7. Either side types `exit`; both loops send one last signed/encrypted `exit`, shut down sockets, and terminate threads.

By cross-referencing the sections above with the linked modules, you can follow every byte from keyboard to wire to screen while seeing the cryptographic protections applied at each boundary.

## 9. Interview Cheat Sheet (Defensive Answers)

- **"Why is the PEM serialization necessary?"** — Because PEM is the de-facto interoperable format for public keys. It is ASCII-safe, includes clear delimiters, and every crypto library understands it, so it guarantees the client can deserialize the server's key without ambiguity.
- **"Why mix RSA and AES instead of only one algorithm?"** — RSA excels at key exchange and signatures but is slow for large payloads; AES is fast and secure for bulk data but requires both parties to already share a secret. Combining them gives the best properties of both worlds.
- **"How do you prevent man-in-the-middle attacks?"** — Both sides exchange and pin each other's public keys before any message exchange. Every message is signed with those keys, so an attacker cannot impersonate either party without the corresponding private key.
- **"What happens if an attacker replays an old encrypted message?"** — AES-GCM's nonce and tag pair will fail verification if reused; additionally, the application-level `exit` command is handled carefully so that a replayed `exit` cannot silently kill a session unless the signature also validates, which only the original sender can produce.
- **"How would you improve this further?"** — Mention adding certificates for long-term identity, implementing perfect forward secrecy with ephemeral Diffie-Hellman, and persisting public-key fingerprints so users can manually verify identities.
