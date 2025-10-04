import argparse
import socket
from threading import Thread

from secure_chat_common import (
    TYPE_KEY,
    TYPE_MESSAGE,
    TYPE_SESSION_KEY,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    deserialize_public_key,
    generate_aes_key,
    recv_frame,
    rsa_encrypt,
    send_frame,
)

run = True


def receiver(sock: socket.socket, aes_key: bytes):
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
            plaintext = aes_gcm_decrypt(aes_key, payload)
            text = plaintext.decode(errors='ignore')
        except Exception:
            print('Received an unreadable/invalid encrypted message.')
            continue
        if text.strip().lower() == 'exit':
            print('Server requested to end chat. Closing client...')
            run = False
            break
        print(f'Message Received: {text}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure chat client (RSA + AES-GCM)')
    parser.add_argument('--host', default='192.168.0.176', help='Server host/IP to connect to')
    parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = args.host
    port = args.port
    s.connect((host, port))
    print(f'Connected to server at {host}:{port}. Type messages and press Enter. Type "exit" to quit.')

    # Step 1: Receive server public key
    frame = recv_frame(s)
    if frame is None:
        raise RuntimeError('Disconnected before receiving server public key')
    ftype, payload = frame
    if ftype != TYPE_KEY:
        raise RuntimeError('Unexpected frame (expected public key)')
    server_pub = deserialize_public_key(payload)

    # Step 2: Generate AES session key and send encrypted with RSA-OAEP
    aes_key = generate_aes_key()
    enc_key = rsa_encrypt(server_pub, aes_key)
    send_frame(s, TYPE_SESSION_KEY, enc_key)

    run = True
    rcv = Thread(target=receiver, args=(s, aes_key), daemon=True)
    rcv.start()

    while run:
        try:
            msg = input('Type Message: ')
            enc = aes_gcm_encrypt(aes_key, msg.encode())
            send_frame(s, TYPE_MESSAGE, enc)
            if msg.strip().lower() == 'exit':
                run = False
                break
        except (EOFError, KeyboardInterrupt):
            try:
                enc = aes_gcm_encrypt(aes_key, b'exit')
                send_frame(s, TYPE_MESSAGE, enc)
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
