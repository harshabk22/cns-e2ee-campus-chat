"""
server.py - Zero-Knowledge Blind Socket Relay Server (Hardened & Reviewed)
Course: Cryptography and Network Security (CNS)

Role:
Operated by Host Machine. Listens on local network port 5555.
Operates as a pure blind relay: routes encrypted JSON envelopes between client
sockets without holding private keys, shared secrets, or decrypting payloads.

Hardened Features:
- Byte-level TCP stream framing using b"\\n" (safe against UTF-8 multi-byte chunk splits).
- Concurrency race-condition safe disconnect handling (prevents unregistering newly reconnected sockets).
- Lock contention elimination: snapshots targets before broadcasting outside the lock.
- DoS buffer limit enforcement (MAX_FRAME_SIZE = 65536).
"""

import socket
import threading
import json
import datetime
import sys

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5555
MAX_FRAME_SIZE = 65536

# Thread-safe dictionary storing active clients: username -> (socket, address)
clients_lock = threading.Lock()
clients = {}


def get_local_ip():
    """Attempts to find the actual local Wi-Fi / LAN IP address of this laptop."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def log(msg):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def send_packet(sock, packet_dict):
    """Encodes and sends a packet with a newline delimiter for TCP stream framing."""
    try:
        data = (json.dumps(packet_dict) + "\n").encode('utf-8')
        sock.sendall(data)
        return True
    except Exception:
        return False


def broadcast_user_list():
    """Sends updated list of online users to all connected clients without lock contention."""
    with clients_lock:
        online_users = list(clients.keys())
        target_sockets = [c_sock for c_sock, _ in clients.values()]

    pkt = {"type": "user_list", "users": online_users}
    for c_sock in target_sockets:
        send_packet(c_sock, pkt)


def handle_client(sock, addr):
    username = None
    buffer = bytearray()
    try:
        # Read registration packet using byte-level line buffering
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                return
            buffer.extend(chunk)
            if len(buffer) > MAX_FRAME_SIZE:
                sock.close()
                return

        reg_line, _, remaining = buffer.partition(b"\n")
        buffer = bytearray(remaining)

        try:
            reg_data = json.loads(reg_line.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            sock.close()
            return

        if reg_data.get("type") != "register":
            sock.close()
            return

        username = reg_data.get("username", "").strip()
        if not username:
            sock.close()
            return

        with clients_lock:
            # If user reconnects, close old connection
            if username in clients:
                old_sock, _ = clients[username]
                try:
                    old_sock.close()
                except Exception:
                    pass
            clients[username] = (sock, addr)

        log(f"🟢 [NEW CLIENT] '{username}' connected from {addr[0]}:{addr[1]}")
        broadcast_user_list()

        # Continuous listening loop with byte-level line-delimited TCP framing
        while True:
            while b"\n" in buffer:
                line, _, remaining = buffer.partition(b"\n")
                buffer = bytearray(remaining)
                line = line.strip()
                if not line:
                    continue

                try:
                    packet = json.loads(line.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    log(f"⚠️  [MALFORMED PACKET] Discarded invalid JSON from '{username}'")
                    continue

                pkt_type = packet.get("type", "message")
                recipient = packet.get("to")

                with clients_lock:
                    target = clients.get(recipient)

                if target:
                    target_sock = target[0]
                    if send_packet(target_sock, packet):
                        if pkt_type == "key_exchange":
                            log(f"🔑 [KEY EXCHANGE] Relayed Diffie-Hellman public key: '{username}' -> '{recipient}'")
                        else:
                            payload_preview = packet.get("ciphertext", "")[:16] + "..."
                            log(f"🛡️  [BLIND RELAY] Forwarded encrypted message from '{username}' -> '{recipient}' (Ciphertext: {payload_preview})")
                    else:
                        log(f"❌ [DELIVERY FAILED] Could not send to '{recipient}' (socket broken)")
                else:
                    log(f"⚠️  [UNDELIVERED] Recipient '{recipient}' is not connected.")
                    err_pkt = {
                        "type": "error",
                        "from": "SERVER",
                        "message": f"User '{recipient}' is currently offline."
                    }
                    send_packet(sock, err_pkt)

            # Read more chunks from network socket
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer.extend(chunk)
            if len(buffer) > MAX_FRAME_SIZE:
                log(f"⚠️  [DoS GUARD] Client '{username}' exceeded max frame buffer limit. Disconnecting.")
                break

    except Exception as e:
        log(f"❌ [CONNECTION ERROR] '{username}': {e}")
    finally:
        with clients_lock:
            # FIX: Only remove from registry if it still points to this thread's socket
            if username and username in clients and clients[username][0] == sock:
                del clients[username]
                log(f"🔴 [DISCONNECTED] '{username}' left the network.")
        broadcast_user_list()
        try:
            sock.close()
        except Exception:
            pass


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python3 server.py [port]")
            sys.exit(1)

    local_ip = get_local_ip()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((DEFAULT_HOST, port))
        server.listen(10)
    except Exception as e:
        print(f"[FATAL] Failed to bind to port {port}: {e}")
        sys.exit(1)

    print("=" * 70)
    print("🔒 ZERO-KNOWLEDGE E2EE BLIND RELAY SERVER - CNS MICRO-PROJECT")
    print("=" * 70)
    print(f"[*] Server Listening on:  {DEFAULT_HOST}:{port}")
    print(f"[*] College Wi-Fi IP:     {local_ip}  (Share this IP with Alice & Bob)")
    print(f"[*] Port:                 {port}")
    print(f"[*] Framing:              Byte-level Newline Delimited JSON (Stream Safe)")
    print(f"[*] Security Policy:      Zero-Knowledge (Plaintext never enters server)")
    print("=" * 70)
    print("[*] Waiting for student chat clients to connect...\n")

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
