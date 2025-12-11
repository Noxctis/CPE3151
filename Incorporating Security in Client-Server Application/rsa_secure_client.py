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


def receiver(sock: socket.socket, private_key, server_public):
    global run
    while run:
        package = recv_package(sock)
        if package is None:
            print('Server disconnected. Closing client...')
            run = False
            break
        ciphertext, signature = package
        if not verify_ciphertext_signature(ciphertext, signature, server_public):
            print('Signature verification failed. Message discarded.')
            continue
        try:
            message = decrypt_message(ciphertext, private_key)
        except Exception as exc:
            print(f'Failed to decrypt message: {exc}')
            continue
        if message.strip().lower() == 'exit':
            print('Server requested to end chat. Closing client...')
            run = False
            break
        print(f'Message Received: {message}')


def send_messages(sock: socket.socket, private_key, server_public):
    global run
    while run:
        try:
            msg = input('Type Message: ')
            ciphertext = encrypt_message(msg, server_public)
            signature = sign_ciphertext(ciphertext, private_key)
            send_package(sock, ciphertext, signature)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            try:
                ciphertext = encrypt_message('exit', server_public)
                signature = sign_ciphertext(ciphertext, private_key)
                send_package(sock, ciphertext, signature)
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RSA encrypted + signed chat client (python-rsa)')
    parser.add_argument('--host', default='127.0.0.1', help='Server host/IP to connect to')
    parser.add_argument('--port', type=int, default=9000, help='Server port to connect to')
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print(f'Connected to server at {args.host}:{args.port}. Type messages and press Enter. Type "exit" to quit.')

    client_public, client_private = generate_keypair()

    # Receive server's public key, then send ours
    server_pem = recv_length_prefixed(sock)
    if server_pem is None:
        raise RuntimeError('Disconnected before receiving server public key')
    server_public = deserialize_public_key(server_pem)
    send_length_prefixed(sock, serialize_public_key(client_public))
    print('Public key exchange complete.')

    run = True
    recv_thread = Thread(target=receiver, args=(sock, client_private, server_public), daemon=True)
    recv_thread.start()

    send_messages(sock, client_private, server_public)
    recv_thread.join(timeout=1)

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    sock.close()
