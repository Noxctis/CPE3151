"""Shared helpers for RSA-encrypted and signed chat using the ``rsa`` package."""

from __future__ import annotations

import rsa
import socket
import struct
from typing import Optional, Tuple

LENGTH_STRUCT = struct.Struct('!I')  # 4-byte big-endian length prefix


# ---------- Key utilities ----------

def generate_keypair(bits: int = 2048) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    """Generate and return (public_key, private_key)."""
    return rsa.newkeys(bits)


def serialize_public_key(public_key: rsa.PublicKey) -> bytes:
    return public_key.save_pkcs1(format='PEM')


def deserialize_public_key(data: bytes) -> rsa.PublicKey:
    return rsa.PublicKey.load_pkcs1(data, format='PEM')


# ---------- Socket framing helpers ----------

def send_length_prefixed(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(LENGTH_STRUCT.pack(len(payload)) + payload)


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
    return b"".join(chunks)


def recv_length_prefixed(sock: socket.socket) -> Optional[bytes]:
    header = recv_exact(sock, LENGTH_STRUCT.size)
    if header is None:
        return None
    (length,) = LENGTH_STRUCT.unpack(header)
    if length < 0:
        return None
    return recv_exact(sock, length)


def send_package(sock: socket.socket, ciphertext: bytes, signature: bytes) -> None:
    """Send ciphertext and signature as two length-prefixed blobs."""
    send_length_prefixed(sock, ciphertext)
    send_length_prefixed(sock, signature)


def recv_package(sock: socket.socket) -> Optional[Tuple[bytes, bytes]]:
    ciphertext = recv_length_prefixed(sock)
    if ciphertext is None:
        return None
    signature = recv_length_prefixed(sock)
    if signature is None:
        return None
    return ciphertext, signature


# ---------- Crypto helpers ----------

def encrypt_message(message: str, peer_public: rsa.PublicKey) -> bytes:
    """Encrypt UTF-8 text with receiver's public key."""
    return rsa.encrypt(message.encode('utf-8'), peer_public)


def decrypt_message(ciphertext: bytes, private_key: rsa.PrivateKey) -> str:
    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext.decode('utf-8', errors='ignore')


def sign_ciphertext(ciphertext: bytes, private_key: rsa.PrivateKey) -> bytes:
    """Sign the ciphertext digest using SHA-256 via python-rsa."""
    return rsa.sign(ciphertext, private_key, 'SHA-256')


def verify_ciphertext_signature(ciphertext: bytes, signature: bytes, peer_public: rsa.PublicKey) -> bool:
    try:
        rsa.verify(ciphertext, signature, peer_public)
        return True
    except rsa.VerificationError:
        return False
