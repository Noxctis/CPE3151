import argparse
import socket
from threading import Thread

from secure_chat_common import (
    TYPE_KEY,
    TYPE_MESSAGE,
    TYPE_SESSION_KEY,
    create_authenticated_message,
    deserialize_public_key,
    generate_rsa_keypair,
    parse_authenticated_message,
    recv_frame,
    rsa_decrypt,
    send_frame,
    serialize_public_key,
)

run = True


def receive_messages(conn: socket.socket, aes_key: bytes, client_pub_key):
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
            plaintext = parse_authenticated_message(payload, aes_key, client_pub_key)
            text = plaintext.decode(errors='ignore')
        except Exception as e:
            print(f'Received an invalid message: {e}')
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


def send_messages(conn: socket.socket, aes_key: bytes, server_private_key):
    global run
    while run:
        try:
            msg = input('Type Message: ')
            auth_msg = create_authenticated_message(msg.encode(), aes_key, server_private_key)
            send_frame(conn, TYPE_MESSAGE, auth_msg)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            # Send exit best-effort
            try:
                auth_msg = create_authenticated_message(b'exit', aes_key, server_private_key)
                send_frame(conn, TYPE_MESSAGE, auth_msg)
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
    parser = argparse.ArgumentParser(description='Secure chat server (RSA + AES-GCM with signatures)')
    parser.add_argument('--host', default='192.168.0.176', help='Host/IP to bind (use 0.0.0.0 to accept from any)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args()

    srv_sock = None
    conn = None
    try:
        # RSA keypair for this session
        server_private_key, server_public_key = generate_rsa_keypair()
        server_pub_pem = serialize_public_key(server_public_key)

        conn, addr, srv_sock = listen_connection(args.host, args.port)

        # Step 1: Send our public key to the client
        send_frame(conn, TYPE_KEY, server_pub_pem)
        
        # Step 2: Receive client public key
        frame = recv_frame(conn)
        if frame is None:
            raise RuntimeError('Client disconnected during key exchange')
        ftype, payload = frame
        if ftype != TYPE_KEY:
            raise RuntimeError('Unexpected frame during handshake (expected client public key)')
        client_pub_key = deserialize_public_key(payload)

        # Step 3: Receive the AES session key, encrypted with our public key
        frame = recv_frame(conn)
        if frame is None:
            raise RuntimeError('Client disconnected during handshake')
        ftype, payload = frame
        if ftype != TYPE_SESSION_KEY:
            raise RuntimeError('Unexpected frame during handshake (expected session key)')
        aes_key = rsa_decrypt(server_private_key, payload)
        if len(aes_key) not in (16, 24, 32):
            raise RuntimeError('Invalid AES key length received')

        # Start chat threads
        rcv = Thread(target=receive_messages, args=(conn, aes_key, client_pub_key), daemon=True)
        rcv.start()
        send_messages(conn, aes_key, server_private_key)
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
