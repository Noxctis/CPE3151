"""Interactive MITM attack proxy for the secure chat demo.

Run this script, point the legit client at LISTEN_PORT, and control the
attack behaviour from the built-in UI (passive/tamper/replay/drop/delay).
"""

import socket
import struct
import threading
import time
from typing import List

# CONFIGURATION
LISTEN_PORT = 8080       # Client connects here
TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8000       # Real Server is here

DELAY_SECONDS = 2.0      # Used by DELAY mode

MODE_DESCRIPTIONS = {
    'passive': 'Straight pass-through (baseline)',
    'tamper': 'Flip last byte of ciphertext to break integrity',
    'replay': 'Forward every ciphertext twice to test replay defense',
    'drop': 'Silently drop chat messages (DoS)',
    'delay': f'Add ~{DELAY_SECONDS}s latency before forwarding',
}

MODE_SHORTCUTS = {
    '0': 'passive', 'p': 'passive',
    '1': 'tamper',  't': 'tamper',
    '2': 'replay',  'r': 'replay',
    '3': 'drop',    'd': 'drop',
    '4': 'delay',   'l': 'delay',
}


class AttackConfig:
    """Thread-safe attack mode registry so UI + proxy threads stay in sync."""

    def __init__(self) -> None:
        self._mode = 'passive'
        self._lock = threading.Lock()

    def set_mode(self, mode: str) -> None:
        if mode not in MODE_DESCRIPTIONS:
            raise ValueError(f'Unknown mode {mode}')
        with self._lock:
            self._mode = mode

    def get_mode(self) -> str:
        with self._lock:
            return self._mode


CONFIG = AttackConfig()

def handle_client(client_socket):
    # Connect to the real server
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((TARGET_HOST, TARGET_PORT))
    except:
        print("❌ Server not running!")
        client_socket.close()
        return

    current_mode = CONFIG.get_mode()
    print(f"[*] Connected. Attack Mode: {current_mode.upper()} - {MODE_DESCRIPTIONS[current_mode]}")

    # Forward Client -> Server (This is where we attack!)
    def client_to_server():
        buffer = bytearray()
        header_len = 5  # 1-byte type + 4-byte length

        def handle_frame(frame_type: int, payload: bytes) -> List[bytes]:
            frame = bytes([frame_type]) + struct.pack('!I', len(payload)) + payload
            frames_to_send = [frame]

            if frame_type == 0x4D:  # 'M'
                mode = CONFIG.get_mode()

                if mode == 'tamper':
                    print(f"[*] Intercepted TYPE_MESSAGE ({len(payload)} bytes). TAMPERING...")
                    mutated = bytearray(frame)
                    mutated[-1] ^= 0xFF
                    frames_to_send = [bytes(mutated)]
                elif mode == 'replay':
                    print(f"[*] Intercepted TYPE_MESSAGE ({len(payload)} bytes). REPLAYING...")
                    frames_to_send = [frame, frame]
                elif mode == 'drop':
                    print(f"[*] Intercepted TYPE_MESSAGE ({len(payload)} bytes). DROPPING...")
                    frames_to_send = []
                elif mode == 'delay':
                    print(f"[*] Intercepted TYPE_MESSAGE ({len(payload)} bytes). DELAYING {DELAY_SECONDS}s...")
                    time.sleep(DELAY_SECONDS)
            return frames_to_send

        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer.extend(data)

                while True:
                    if len(buffer) < header_len:
                        break
                    frame_type = buffer[0]
                    payload_len = struct.unpack('!I', buffer[1:5])[0]
                    total_len = header_len + payload_len
                    if len(buffer) < total_len:
                        break

                    payload = bytes(buffer[5:total_len])
                    del buffer[:total_len]

                    for out_frame in handle_frame(frame_type, payload):
                        server_socket.sendall(out_frame)
        except Exception as exc:
            print(f"[!] client_to_server exception: {exc}")
        finally:
            server_socket.close()

    # Forward Server -> Client (Pass through)
    def server_to_client():
        try:
            while True:
                data = server_socket.recv(4096)
                if not data: break
                client_socket.sendall(data)
        except:
            pass
        finally:
            client_socket.close()

    t1 = threading.Thread(target=client_to_server, daemon=True)
    t2 = threading.Thread(target=server_to_client, daemon=True)
    t1.start()
    t2.start()

def start_server():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(('0.0.0.0', LISTEN_PORT))
    proxy.listen(5)
    print(f"🔥 Attack Tool Listening on {LISTEN_PORT} -> Target {TARGET_PORT}")
    
    while True:
        client, _ = proxy.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


def print_menu():
    print("\n=== Attack Control Panel ===")
    print('  [0/p] PASSIVE  -> ' + MODE_DESCRIPTIONS['passive'])
    print('  [1/t] TAMPER   -> ' + MODE_DESCRIPTIONS['tamper'])
    print('  [2/r] REPLAY   -> ' + MODE_DESCRIPTIONS['replay'])
    print('  [3/d] DROP     -> ' + MODE_DESCRIPTIONS['drop'])
    print('  [4/l] DELAY    -> ' + MODE_DESCRIPTIONS['delay'])
    print('  [s]   STATUS   -> Show current mode')
    print('  [h]   HELP     -> Reprint this menu')
    print('  [Ctrl+C]       -> Quit tool\n')


def ui_loop():
    print_menu()
    while True:
        try:
            cmd = input('[attack-mode] Enter option: ').strip().lower()
        except EOFError:
            break
        if not cmd:
            continue
        if cmd in MODE_SHORTCUTS:
            mode = MODE_SHORTCUTS[cmd]
            CONFIG.set_mode(mode)
            print(f"[UI] Attack mode set to {mode.upper()} - {MODE_DESCRIPTIONS[mode]}")
        elif cmd == 's':
            mode = CONFIG.get_mode()
            print(f"[UI] Current mode: {mode.upper()} - {MODE_DESCRIPTIONS[mode]}")
        elif cmd == 'h':
            print_menu()
        else:
            print('[UI] Unknown command. Press h for help.')

if __name__ == '__main__':
    ui_thread = threading.Thread(target=ui_loop, daemon=True)
    ui_thread.start()
    start_server()