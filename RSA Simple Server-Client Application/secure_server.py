import argparse
import socket
from threading import Thread

from secure_chat_common import (
    TYPE_KEY,
    TYPE_MESSAGE,
    TYPE_SESSION_KEY,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_rsa_keypair,
    recv_frame,
    rsa_decrypt,
    send_frame,
    serialize_public_key,
)

run = True


def receive_messages(conn: socket.socket, aes_key: bytes):
    global run
    while run:
        frame = recv_frame(conn)
        if frame is None:
            print('Peer disconnected. Closing server...')
            run = False
            break
        ftype, payload = frame
        if ftype != TYPE_MESSAGE:
            # Ignore unexpected frames after handshake
            continue
        try:
            plaintext = aes_gcm_decrypt(aes_key, payload)
            text = plaintext.decode(errors='ignore')
        except Exception:
            print('Received an unreadable/invalid encrypted message.')
            continue
        if text.strip().lower() == 'exit':
            print('Peer requested to end chat. Closing server...')
            run = False
            break
        print(f'Message Received: {text}')

    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


def send_messages(conn: socket.socket, aes_key: bytes):
    global run
    while run:
        try:
            msg = input('Type Message: ')
            enc = aes_gcm_encrypt(aes_key, msg.encode())
            send_frame(conn, TYPE_MESSAGE, enc)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            # Send exit best-effort
            try:
                enc = aes_gcm_encrypt(aes_key, b'exit')
                send_frame(conn, TYPE_MESSAGE, enc)
            except Exception:
                pass
            run = False
            break
        except OSError:
            run = False
            break


def listen_connection(host: str = '192.168.0.176', port: int = 8000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print(f'Server listening on {host}:{port} ...')
    s.listen(1)
    conn, addr = s.accept()
    print(f'Server accepted client connection from {addr[0]}:{addr[1]}')
    return conn, addr, s


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure chat server (RSA + AES-GCM)')
    parser.add_argument('--host', default='192.168.0.176', help='Host/IP to bind (use 0.0.0.0 to accept from any)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args()

    srv_sock = None
    conn = None
    try:
        # RSA keypair for this session
        private_key, public_key = generate_rsa_keypair()
        public_pem = serialize_public_key(public_key)

        conn, addr, srv_sock = listen_connection(args.host, args.port)

        # Step 1: Send our public key to the client
        send_frame(conn, TYPE_KEY, public_pem)

        # Step 2: Receive the AES session key, encrypted with our public key
        frame = recv_frame(conn)
        if frame is None:
            raise RuntimeError('Client disconnected during handshake')
        ftype, payload = frame
        if ftype != TYPE_SESSION_KEY:
            raise RuntimeError('Unexpected frame during handshake (expected session key)')
        aes_key = rsa_decrypt(private_key, payload)
        if len(aes_key) not in (16, 24, 32):
            raise RuntimeError('Invalid AES key length received')

        # Start chat threads
        rcv = Thread(target=receive_messages, args=(conn, aes_key), daemon=True)
        rcv.start()
        send_messages(conn, aes_key)
        rcv.join(timeout=1)
    finally:
        try:
            if conn:
                conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            if srv_sock:
                srv_sock.close()
        except Exception:
            pass
