"""
Shared utilities for a secure chat using RSA (for key exchange) and AES-GCM (for message encryption).

Protocol framing
----------------
All data sent over the socket after TCP connect uses a simple framed protocol:

- Header: 1 byte frame type + 4 bytes big-endian payload length
- Payload: variable length bytes

Frame types:
- 'K' (0x4B): RSA public key in PEM format (plaintext, not encrypted)
- 'S' (0x53): Session key encrypted with peer's RSA public key (ciphertext)
- 'M' (0x4D): Encrypted chat message using AES-GCM; payload = 12-byte nonce + ciphertext+tag

RSA
---
We use 2048-bit keys and OAEP with SHA-256 for encryption/decryption.

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


# -------------- AES-GCM helpers --------------

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
