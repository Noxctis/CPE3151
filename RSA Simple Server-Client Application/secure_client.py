import argparse
import socket
from threading import Thread

from secure_chat_common import (
    TYPE_KEY,
    TYPE_MESSAGE,
    TYPE_SESSION_KEY,
    create_authenticated_message,
    deserialize_public_key,
    generate_aes_key,
    generate_rsa_keypair,
    parse_authenticated_message,
    recv_frame,
    rsa_encrypt,
    send_frame,
    serialize_public_key,
)

run = True


def receiver(sock: socket.socket, aes_key: bytes, server_pub_key):
    global run
    while run:
        frame = recv_frame(sock)
        if frame is None:
            print('Server disconnected. Closing client...')
            run = False
            break
        ftype, payload = frame
        if ftype != TYPE_MESSAGE:
            continue
        try:
            plaintext = parse_authenticated_message(payload, aes_key, server_pub_key)
            text = plaintext.decode(errors='ignore')
        except Exception as e:
            print(f'Received an invalid message: {e}')
            continue
        if text.strip().lower() == 'exit':
            print('Server requested to end chat. Closing client...')
            run = False
            break
        print(f'Message Received: {text}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure chat client (RSA + AES-GCM with signatures)')
    parser.add_argument('--host', default='127.0.0.1', help='Server host/IP to connect to')
    parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = args.host
    port = args.port
    s.connect((host, port))
    print(f'Connected to server at {host}:{port}. Type messages and press Enter. Type "exit" to quit.')

    # Step 1: Generate client's RSA keypair
    client_private_key, client_public_key = generate_rsa_keypair()
    client_pub_pem = serialize_public_key(client_public_key)
    
    # Step 2: Send client public key to server
    send_frame(s, TYPE_KEY, client_pub_pem)
    
    # Step 3: Receive server public key
    frame = recv_frame(s)
    if frame is None:
        raise RuntimeError('Disconnected before receiving server public key')
    ftype, payload = frame
    if ftype != TYPE_KEY:
        raise RuntimeError('Unexpected frame (expected public key)')
    server_pub_key = deserialize_public_key(payload)

    # Step 4: Generate AES session key and send encrypted with RSA-OAEP
    aes_key = generate_aes_key()
    enc_key = rsa_encrypt(server_pub_key, aes_key)
    send_frame(s, TYPE_SESSION_KEY, enc_key)

    run = True
    rcv = Thread(target=receiver, args=(s, aes_key, server_pub_key), daemon=True)
    rcv.start()

    while run:
        try:
            msg = input('Type Message: ')
            auth_msg = create_authenticated_message(msg.encode(), aes_key, client_private_key)
            send_frame(s, TYPE_MESSAGE, auth_msg)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            try:
                auth_msg = create_authenticated_message(b'exit', aes_key, client_private_key)
                send_frame(s, TYPE_MESSAGE, auth_msg)
            except Exception:
                pass
            run = False
            break
        except OSError:
            run = False
            break

    try:
        s.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    s.close()
