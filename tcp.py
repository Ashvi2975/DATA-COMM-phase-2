import socket
import threading
import json
import os
import hashlib
from datetime import datetime
 
# ===== Color Palette =====
COLORS = [
    "\033[91m",  # red
    "\033[92m",  # green
    "\033[93m",  # yellow
    "\033[94m",  # blue
    "\033[95m",  # magenta
    "\033[96m",  # cyan
    "\033[38;5;208m",  # orange
    "\033[38;5;206m",  # pink
    "\033[38;5;118m",  # light green
    "\033[38;5;39m",   # ocean blue
]
RESET = "\033[0m"
 
# ====== Config ======
TCP_PORT = 13000
BUFFER = 1024
USER_FILE = "users.json"
 
tcp_clients = {}   # username -> conn object (None for server)
user_colors = {}  # username -> ANSI color
 
pending_auth = {}  # temporary holding for login/register connections
 
 
# ====== Helpers ======
def timestamp():
    return datetime.now().strftime("[%I:%M %p]")
 
 
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
 
 
def load_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as f:
            json.dump({}, f)
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)
 
 
def save_users(data):
    with open(USER_FILE, "w") as f:
        json.dump(data, f, indent=2)
 
 
def format_msg(sender, target, msg, private=False):
    tag = "[PRIVATE]" if private else ""
    return f"{timestamp()} {tag} [{sender} → {target}] {msg}".strip()
 
 
def broadcast_tcp(msg, sender=None):
    print(msg)
    for user, conn in list(tcp_clients.items()):
        if user == sender:
            continue
        if conn:
            try:
                conn.sendall((msg + "\n").encode())
            except:
                tcp_clients.pop(user, None)
 
 
def private_msg_tcp(sender, target, msg):
 
    # ---- Handle non-existent user ----
    if target not in tcp_clients:
        # reply only to sender
        if sender in tcp_clients and tcp_clients[sender]:
            tcp_clients[sender].sendall(f"[System] User '{target}' not found.\n".encode())
        else:
            print(f"[System] User '{target}' not found.")  # sender is server
        return
 
    m = format_msg(sender, target, msg, private=True)
 
    # ---- Target is server ----
    if tcp_clients[target] is None:
        print(m)  # show on server console
        if sender in tcp_clients and tcp_clients[sender]:
            tcp_clients[sender].sendall((m + "\n").encode())
        return
 
    # ---- Send to target ----
    try:
        tcp_clients[target].sendall((m + "\n").encode())
    except:
        pass
 
    # ---- Echo to sender ----
    if sender in tcp_clients and tcp_clients[sender]:
        try:
            tcp_clients[sender].sendall((m + "\n").encode())
        except:
            pass
    else:
        print(m)
 
 
# ====== AUTH ======
def handle_auth_request(conn, addr):
    """
    Handles AUTH REGISTER and AUTH LOGIN.
    Returns (username, conn) if approved, else None.
    """
    try:
        raw = conn.recv(BUFFER).decode().strip()
    except:
        return None
 
    if not raw.startswith("AUTH"):
        conn.sendall(b"AUTH FAIL Invalid auth format.\n")
        conn.close()
        return None
 
    parts = raw.split()
    if len(parts) != 4:
        conn.sendall(b"AUTH FAIL Invalid auth syntax.\n")
        conn.close()
        return None
 
    _, mode, username, password = parts
    username = username.lower().strip()
 
    users = load_users()
 
    # REGISTER
    if mode.upper() == "REGISTER":
        if username in users:
            conn.sendall(b"AUTH FAIL User already exists.\n")
            conn.close()
            return None
        users[username] = hash_pw(password)
        save_users(users)
        conn.sendall(b"AUTH REGISTERED\n")
 
    # LOGIN
    elif mode.upper() == "LOGIN":
        if username not in users:
            conn.sendall(b"AUTH FAIL User does not exist.\n")
            conn.close()
            return None
        if users[username] != hash_pw(password):
            conn.sendall(b"AUTH FAIL Incorrect password.\n")
            conn.close()
            return None
        conn.sendall(b"AUTH OK\n")
    else:
        conn.sendall(b"AUTH FAIL Unknown mode.\n")
        conn.close()
        return None
 
    # Approval required
    print(f"\n[AUTH REQUEST] User \"{username}\" wants to {mode.upper()}.")
    while True:
        decision = input(f"Approve {username}? (y/n): ").strip().lower()
        if decision == "y":
            conn.sendall(b"AUTH APPROVED\n")
            return username
        if decision == "n":
            conn.sendall(b"AUTH REJECTED\n")
            conn.close()
            return None
        print("Type y or n.")
 
    return None
 
 
# ====== Client Thread ======
def handle_tcp_client(username, conn, addr):
    tcp_clients[username] = conn
    broadcast_tcp(format_msg("System", "All", f"{username} joined the chat."))
 
    conn.sendall(b"\nCommands:\n"
                 b"  /who          - List online users\n"
                 b"  @name msg     - Private message\n"
                 b"  exit          - Leave chat\n\n")
 
    while True:
        try:
            data = conn.recv(BUFFER)
        except:
            break
        if not data:
            break
 
        msg = data.decode().strip()
        if not msg:
            conn.sendall(b"[System] Cannot send blank message.\n")
            continue
 
        # exit
        if msg.lower() == "exit":
            break
 
        # /who
        if msg == "/who":
            users = ", ".join(tcp_clients.keys())
            conn.sendall(f"[System] Online: {users}\n".encode())
            continue
 
        # private
        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            if len(parts) == 2:
                target = parts[0][1:]
                private_msg_tcp(username, target, parts[1])
            else:
                conn.sendall(b"[System] Usage: @username message\n")
            continue
 
        # public msg
        broadcast_tcp(format_msg(username, "All", msg), sender=username)
 
    conn.close()
    tcp_clients.pop(username, None)
    broadcast_tcp(format_msg("System", "All", f"{username} left the chat."))
 
 
# ====== Server Chat Input ======
def server_chat_input(name):
    while True:
        msg = input().strip()
        if not msg:
            print("[System] Cannot send blank message.")
            continue
 
        if msg.lower() == "exit":
            print("🚪 Server shutting down...")
            for conn in list(tcp_clients.values()):
                if conn:
                    conn.close()
            os._exit(0)
 
        if msg == "/who":
            users = ", ".join(tcp_clients.keys())
            print(f"[System] Online: {users}")
            continue
 
        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            if len(parts) == 2:
                private_msg_tcp(name, parts[0][1:], parts[1])
            else:
                print("[System] Usage: @username message")
            continue
 
        broadcast_tcp(format_msg(name, "All", msg), sender=name)
 
 
# ====== Run Server ======
def run_tcp_server():
    name = input("Enter server name: ").strip() or "Server"
 
    tcp_clients[name] = None  # server appears as user
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", TCP_PORT))
    s.listen(5)
 
    print(f"{timestamp()} [{name}] TCP server running on port {TCP_PORT}")
 
    threading.Thread(target=server_chat_input, args=(name,), daemon=True).start()
 
    while True:
        conn, addr = s.accept()
 
        # Step 1: AUTH
        username = handle_auth_request(conn, addr)
        if not username:
            continue
 
        # Step 2: Start chat thread
        threading.Thread(target=handle_tcp_client, args=(username, conn, addr), daemon=True).start()
import socket
import threading
 
TCP_PORT = 13000
BUFFER = 1024
 
 
def recv_tcp(sock):
    while True:
        try:
            data = sock.recv(BUFFER)
            if not data:
                print("\n[System] Disconnected.")
                break
            print("\n" + data.decode().strip())
        except:
            break
 
 
def tcp_client(ip):
    print("\nLogin or Register:")
    print("  l = login")
    print("  r = register\n")
 
    mode = ""
    while mode not in ("l", "r"):
        mode = input("Choose (l/r): ").lower().strip()
 
    username = input("Username: ").strip().lower()
    password = input("Password: ").strip()
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
    try:
        s.connect((ip, TCP_PORT))
    except:
        print("[System] Cannot connect to server.")
        return
 
    # send auth command
    if mode == "l":
        s.sendall(f"AUTH LOGIN {username} {password}".encode())
    else:
        s.sendall(f"AUTH REGISTER {username} {password}".encode())
 
    # wait for response
    while True:
        try:
            res = s.recv(BUFFER).decode().strip()
        except:
            print("[System] Server closed connection.")
            return
 
        if res.startswith("AUTH FAIL"):
            print(res)
            s.close()
            return
 
        if res == "AUTH REGISTERED":
            print("[System] Registered. Waiting for approval...")
            continue
 
        if res == "AUTH OK":
            print("[System] Login OK. Waiting for approval...")
            continue
 
        if res == "AUTH APPROVED":
            print("[System] Approved. Entering chat...\n")
            break
 
        if res == "AUTH REJECTED":
            print("[System] Your login was rejected by the server.")
            s.close()
            return
 
    threading.Thread(target=recv_tcp, args=(s,), daemon=True).start()
 
    while True:
        msg = input().strip()
        if not msg:
            print("[System] Cannot send blank message.")
            continue
 
        s.sendall(msg.encode())
 
        if msg.lower() == "exit":
            s.close()
            break
        return
 
 