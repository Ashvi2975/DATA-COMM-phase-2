import socket
import ssl
import threading
import json
import os
import hashlib
import sys
import logging
from datetime import datetime

# ====== Config ======
TCP_PORT = 14400
BUFFER = 1024
USER_FILE = "users.json"

tcp_clients = {}  # username -> TLS socket
SERVER_NAME = "Server"  # updated at runtime


# ===== Logging Setup =====
logger = logging.getLogger("ChatServer")
logger.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler("server.log", encoding="utf-8")
file_handler.setLevel(logging.INFO)

# Console handler (UTF-8 forced for Windows)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setStream(open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1))
console_handler.setLevel(logging.INFO)

# Log format
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


# ===== Helpers =====
def timestamp():
    return datetime.now().strftime("[%I:%M %p]")


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    if not os.path.exists(USER_FILE):
        json.dump({}, open(USER_FILE, "w"))
        return {}
    return json.load(open(USER_FILE))


def save_users(data):
    json.dump(data, open(USER_FILE, "w"), indent=2)


def format_msg(sender, target, msg, private=False):
    tag = "[PRIVATE]" if private else ""
    return f"{timestamp()} {tag} [{sender} → {target}] {msg}"


def broadcast(msg, sender=None):
    logger.info(msg)

    for user, conn in list(tcp_clients.items()):
        if user == sender:
            continue
        try:
            conn.send((msg + "\n").encode())
        except:
            tcp_clients.pop(user, None)


def private_msg(sender, target, msg):
    original_target = target
    target = target.lower()
    formatted = format_msg(sender, original_target, msg, private=True)

    logger.info(formatted)

    if target == SERVER_NAME.lower():
        if sender in tcp_clients:
            tcp_clients[sender].send((formatted + "\n").encode())
        return

    if target not in tcp_clients:
        if sender in tcp_clients:
            tcp_clients[sender].send(f"[System] User '{original_target}' not found.\n".encode())
        return

    tcp_clients[target].send((formatted + "\n").encode())
    if sender in tcp_clients:
        tcp_clients[sender].send((formatted + "\n").encode())


# ===== AUTH =====
def handle_auth(conn):
    try:
        raw = conn.recv(BUFFER).decode().strip()
    except:
        return None

    if not raw.startswith("AUTH"):
        conn.send(b"AUTH FAIL Invalid auth format.\n")
        conn.close()
        return None

    parts = raw.split()
    if len(parts) != 4:
        conn.send(b"AUTH FAIL Invalid auth syntax.\n")
        conn.close()
        return None

    _, mode, username, password = parts
    username = username.lower()

    users = load_users()

    if mode.upper() == "REGISTER":
        if username in users:
            conn.send(b"AUTH FAIL User exists.\n")
            conn.close()
            return None
        users[username] = hash_pw(password)
        save_users(users)
        conn.send(b"AUTH REGISTERED\n")

    elif mode.upper() == "LOGIN":
        if username not in users:
            conn.send(b"AUTH FAIL User does not exist.\n")
            conn.close()
            return None
        if users[username] != hash_pw(password):
            conn.send(b"AUTH FAIL Incorrect password.\n")
            conn.close()
            return None
        conn.send(b"AUTH OK\n")

    else:
        conn.send(b"AUTH FAIL Unknown mode.\n")
        conn.close()
        return None

    logger.info(f"[AUTH REQUEST] User '{username}' wants to {mode.upper()}.")

    while True:
        choice = input(f"Approve {username}? (y/n): ").lower()
        if choice == "y":
            conn.send(b"AUTH APPROVED\n")
            return username
        if choice == "n":
            conn.send(b"AUTH REJECTED\n")
            conn.close()
            return None
        print("Type y or n.")


# ===== Server Client Thread =====
def handle_client(username, conn):
    broadcast(format_msg("System", "All", f"{username} joined."))
    logger.info(f"{username} joined.")

    conn.send(b"\nCommands:\n  /who\n  @user msg\n  exit\n\n")

    while True:
        try:
            data = conn.recv(BUFFER)
        except:
            break
        if not data:
            break

        msg = data.decode().strip()

        if msg.lower() == "exit":
            break

        if msg == "/who":
            conn.send(f"[System] Online: {', '.join(tcp_clients.keys())}\n".encode())
            continue

        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            if len(parts) == 2:
                private_msg(username, parts[0][1:], parts[1])
            else:
                conn.send(b"[System] Usage: @user text\n")
            continue

        broadcast(format_msg(username, "All", msg), sender=username)

    conn.close()
    tcp_clients.pop(username, None)
    broadcast(format_msg("System", "All", f"{username} left."))
    logger.info(f"{username} left.")


# ===== Server Console =====
def server_console(name):
    while True:
        msg = input().strip()

        if msg == "/who":
            print("[System] Online:", ", ".join(tcp_clients.keys()))
            continue

        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            private_msg(name, parts[0][1:], parts[1])
            continue

        if msg.lower() == "exit":
            logger.info("Server shutting down.")
            os._exit(0)

        broadcast(format_msg(name, "All", msg), sender=name)


# ===== START SERVER =====
def start_server():
    global SERVER_NAME

    SERVER_NAME = input("Server name: ") or "Server"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", TCP_PORT))
    sock.listen(5)

    logger.info(f"{SERVER_NAME} TLS server running on port {TCP_PORT}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.crt", "server.key")

    threading.Thread(target=server_console, args=(SERVER_NAME,), daemon=True).start()

    while True:
        raw_conn, addr = sock.accept()

        try:
            tls_conn = context.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError:
            raw_conn.close()
            continue

        username = handle_auth(tls_conn)
        if not username:
            tls_conn.close()
            continue

        tcp_clients[username] = tls_conn

        threading.Thread(target=handle_client, args=(username, tls_conn), daemon=True).start()


# ===== CLIENT RECEIVER =====
def recv_loop(sock):
    while True:
        try:
            data = sock.recv(BUFFER)
            if not data:
                print("\n[System] Disconnected.")
                break
            print("\n" + data.decode().strip())
        except:
            break


# ===== START CLIENT =====
def start_client(ip):
    print("\nLogin or Register:")
    print("  l = login")
    print("  r = register\n")

    mode = ""
    while mode not in ("l", "r"):
        mode = input("Choose (l/r): ").lower().strip()

    username = input("Username: ").strip().lower()
    password = input("Password: ").strip()

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw_sock.connect((ip, TCP_PORT))
        tls_sock = context.wrap_socket(raw_sock, server_hostname=ip)
    except Exception as e:
        print("[System] Cannot connect:", e)
        return

    if mode == "l":
        tls_sock.send(f"AUTH LOGIN {username} {password}".encode())
    else:
        tls_sock.send(f"AUTH REGISTER {username} {password}".encode())

    while True:
        try:
            res = tls_sock.recv(BUFFER).decode().strip()
        except:
            print("[System] Server disconnected.")
            return

        if res.startswith("AUTH FAIL"):
            print(res)
            tls_sock.close()
            return

        if res in ("AUTH REGISTERED", "AUTH OK"):
            print("[System] Waiting for approval...")
            continue

        if res == "AUTH REJECTED":
            print("[System] Rejected by server.")
            tls_sock.close()
            return

        if res == "AUTH APPROVED":
            print("[System] Approved.\n")
            break

    threading.Thread(target=recv_loop, args=(tls_sock,), daemon=True).start()

    while True:
        msg = input().strip()
        if not msg:
            print("[System] Cannot send blank.")
            continue

        tls_sock.send(msg.encode())

        if msg.lower() == "exit":
            tls_sock.close()
            break


# ===== Entry Point =====
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:\n  python tls_chat.py server\n  python tls_chat.py client <ip>")
        sys.exit()

    mode = sys.argv[1].lower()

    if mode == "server":
        start_server()
    elif mode == "client":
        if len(sys.argv) < 3:
            print("Usage: python tls_chat.py client <ip>")
            sys.exit()
        start_client(sys.argv[2])
    else:
        print("Invalid mode. Use: server / client")
