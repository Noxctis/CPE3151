import socket
import argparse
from threading import Thread


def receiver(sock):
    global run
    while run:
        try:
            data = sock.recv(1024)
            if not data:
                print('Server disconnected. Closing client...')
                run = False
                break
            text = data.decode(errors='ignore')
            if text.strip().lower() == 'exit':
                print('Server requested to end chat. Closing client...')
                run = False
                break
            print(f"Message Received: {text}")
        except socket.error:
            run = False
            break
        except KeyboardInterrupt:
            run = False
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple chat client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host/IP to connect to')
    parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = args.host
    port = args.port
    s.connect((host, port))
    print(f'Connected to server at {host}:{port}. Type messages and press Enter. Type "exit" to quit.')
    run = True

    rcv = Thread(target=receiver, args=(s,), daemon=True)
    rcv.start()

    while run:
        try:
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                try:
                    s.sendall(msg.encode())
                except Exception:
                    pass
                run = False
                break
            s.sendall(msg.encode())
        except EOFError:
            run = False
            break
        except socket.error:
            run = False
            break
        except KeyboardInterrupt:
            run = False
            break

    try:
        s.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    s.close()