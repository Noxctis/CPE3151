import argparse
import socket
from threading import Thread

from rsa_secure_common import (
    decrypt_message,
    encrypt_message,
    generate_keypair,
    recv_length_prefixed,
    recv_package,
    send_length_prefixed,
    send_package,
    serialize_public_key,
    deserialize_public_key,
    sign_ciphertext,
    verify_ciphertext_signature,
)

run = True


def receive_messages(conn: socket.socket, private_key, client_public):
    global run
    while run:
        package = recv_package(conn)
        if package is None:
            print('Client disconnected. Closing server...')
            run = False
            break
        ciphertext, signature = package
        if not verify_ciphertext_signature(ciphertext, signature, client_public):
            print('Signature verification failed. Message discarded.')
            continue
        try:
            message = decrypt_message(ciphertext, private_key)
        except Exception as exc:
            print(f'Failed to decrypt message: {exc}')
            continue
        if message.strip().lower() == 'exit':
            print('Client requested to end chat. Closing server...')
            run = False
            break
        print(f'Message Received: {message}')

    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


def send_messages(conn: socket.socket, private_key, client_public):
    global run
    while run:
        try:
            msg = input('Type Message: ')
            ciphertext = encrypt_message(msg, client_public)
            signature = sign_ciphertext(ciphertext, private_key)
            send_package(conn, ciphertext, signature)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            try:
                ciphertext = encrypt_message('exit', client_public)
                signature = sign_ciphertext(ciphertext, private_key)
                send_package(conn, ciphertext, signature)
            except Exception:
                pass
            run = False
            break
        except OSError:
            run = False
            break
        except Exception as exc:
            print(f'Send error: {exc}')
            run = False
            break


def listen_connection(host: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    print(f'Server listening on {host}:{port} ...')
    srv.listen(1)
    conn, addr = srv.accept()
    print(f'Server accepted client connection from {addr[0]}:{addr[1]}')
    return conn, addr, srv


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RSA encrypted + signed chat server (python-rsa)')
    parser.add_argument('--host', default='127.0.0.1', help='Host/IP to bind (use 0.0.0.0 to accept from any)')
    parser.add_argument('--port', type=int, default=9000, help='Port to listen on')
    args = parser.parse_args()

    srv_sock = None
    conn = None
    try:
        server_public, server_private = generate_keypair()
        conn, addr, srv_sock = listen_connection(args.host, args.port)

        # Exchange public keys: server sends first
        send_length_prefixed(conn, serialize_public_key(server_public))
        client_pem = recv_length_prefixed(conn)
        if client_pem is None:
            raise RuntimeError('Client disconnected before sending its public key')
        client_public = deserialize_public_key(client_pem)
        print('Public key exchange complete.')

        receiver_thread = Thread(target=receive_messages, args=(conn, server_private, client_public), daemon=True)
        receiver_thread.start()
        send_messages(conn, server_private, client_public)
        receiver_thread.join(timeout=1)
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
