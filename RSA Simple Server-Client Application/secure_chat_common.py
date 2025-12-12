"""
Shared utilities for a secure chat using RSA (for key exchange and signatures) and AES-GCM (for message encryption).

Protocol framing
----------------
All data sent over the socket after TCP connect uses a simple framed protocol:

- Header: 1 byte frame type + 4 bytes big-endian payload length
- Payload: variable length bytes

Frame types:
- 'K' (0x4B): RSA public key in PEM format (plaintext, not encrypted)
- 'S' (0x53): Session key encrypted with peer's RSA public key (ciphertext)
- 'M' (0x4D): Authenticated encrypted message using AES-GCM + RSA-PSS signature
  Payload structure: 4-byte signature length + signature + 12-byte nonce + ciphertext+tag

RSA
---
We use 2048-bit keys:
- OAEP with SHA-256 for encryption/decryption (key exchange)
- PSS with SHA-256 for signing/verification (authentication)

AES-GCM
-------
We use 256-bit keys and a 12-byte random nonce per message. Associated data is not used.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Frame type byte values (as integers)
TYPE_KEY = ord('K')       # public key PEM
TYPE_SESSION_KEY = ord('S')  # AES session key encrypted with RSA
TYPE_MESSAGE = ord('M')   # AES-GCM encrypted message


# -------------- RSA helpers --------------
# Authentication & Non-repudiation: these RSA primitives provide identities via signatures
# Confidentiality (during key exchange): RSA-OAEP protects the AES session key in transit

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_data)


def rsa_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# -------------- Digital Signature helpers (Authentication / Non-repudiation) --------------
# Integrity + Authentication: RSA-PSS signatures let receivers verify origin and detect tampering

def sign_hash(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign data using RSA-PSS with SHA-256. Returns the signature."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS signature with SHA-256. Returns True if valid, False otherwise."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# -------------- AES-GCM helpers --------------
# Confidentiality + Integrity: AES-GCM encrypts payloads and supplies an authentication tag per message

def generate_aes_key() -> bytes:
    return os.urandom(32)  # 256-bit key


def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext  # receiver will split nonce and ciphertext+tag


def aes_gcm_decrypt(aes_key: bytes, data: bytes) -> bytes:
    if len(data) < 12:
        raise ValueError("Invalid AES-GCM payload: too short")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -------------- Authenticated Message helpers (Signature + Encryption) --------------
# This layer glues confidentiality (AES-GCM) with authentication/non-repudiation (RSA-PSS) per message

def create_authenticated_message(
    plaintext: bytes,
    aes_key: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """
    Create an authenticated encrypted message.
    
    Returns: signature_length (4 bytes) + signature + encrypted_data
    where encrypted_data = nonce (12 bytes) + AES-GCM ciphertext+tag
    """
    # Encrypt the message
    encrypted_data = aes_gcm_encrypt(aes_key, plaintext)
    
    # Sign the encrypted data (this is what we're authenticating)
    signature = sign_hash(private_key, encrypted_data)
    
    # Frame: [signature_length (4 bytes)] [signature] [encrypted_data]
    sig_len = struct.pack('!I', len(signature))
    return sig_len + signature + encrypted_data


def parse_authenticated_message(
    data: bytes,
    aes_key: bytes,
    peer_public_key: rsa.RSAPublicKey,
) -> bytes:
    """
    Parse and verify an authenticated encrypted message.
    
    Expects: signature_length (4 bytes) + signature + encrypted_data
    
    Returns: plaintext if signature is valid
    Raises: ValueError if signature verification fails
    """
    if len(data) < 4:
        raise ValueError("Invalid authenticated message: too short")
    
    # Extract signature length
    sig_len = struct.unpack('!I', data[:4])[0]
    
    if len(data) < 4 + sig_len:
        raise ValueError("Invalid authenticated message: signature incomplete")
    
    # Extract signature and encrypted data
    signature = data[4:4 + sig_len]
    encrypted_data = data[4 + sig_len:]
    
    # Verify signature on the encrypted data
    if not verify_signature(peer_public_key, encrypted_data, signature):
        raise ValueError("Signature verification failed: message authentication failed")
    
    # Decrypt the message
    plaintext = aes_gcm_decrypt(aes_key, encrypted_data)
    return plaintext


# -------------- Framing helpers --------------

HEADER_STRUCT = struct.Struct('!BI')  # type (1 byte) + length (4 bytes, big-endian)


def send_frame(sock: socket.socket, frame_type: int, payload: bytes) -> None:
    header = HEADER_STRUCT.pack(frame_type, len(payload))
    sock.sendall(header + payload)


def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except (ConnectionResetError, OSError):
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def recv_frame(sock: socket.socket) -> Optional[Tuple[int, bytes]]:
    header = recv_exact(sock, HEADER_STRUCT.size)
    if header is None:
        return None
    ftype, length = HEADER_STRUCT.unpack(header)
    if length < 0:
        return None
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return ftype, payload
