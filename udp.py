import socket
import threading
from datetime import datetime

# ====== Config ======
UDP_PORT = 12000
BUFFER = 1024

# ====== State ======
udp_clients: dict[str, tuple[str, int]] = {}   # username -> (ip, port)
_server_name = "Server"                         # gets set on run_udp_server()

# ====== Helpers ======
def timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def format_msg(sender, target, msg, private=False):
    tag = "[PRIVATE]" if private else ""
    return f"{timestamp()} {tag} [{sender} → {target}] {msg}".strip()

def _safe_sendto(sock: socket.socket, data: str, addr: tuple[str, int] | None):
    """Send safely; never raise to caller."""
    if not addr:
        return
    try:
        sock.sendto((data if data.endswith("\n") else data + "\n").encode(), addr)
    except Exception:
        # swallow — we don't want tracebacks; broadcast will prune on next failure
        pass

def _system_to(sock: socket.socket, addr: tuple[str, int] | None, text: str):
    _safe_sendto(sock, f"[System] {text}", addr)

# ====== Broadcast / Private ======
def broadcast_udp(s: socket.socket, msg: str, sender: str | None = None):
    """Broadcast to all users except optional 'sender'. Prints once on server."""
    print(msg)
    for user, addr in list(udp_clients.items()):
        if sender is not None and user == sender:
            continue
        try:
            _safe_sendto(s, msg, addr)
        except Exception:
            # Remove unreachable user silently (no traceback)
            udp_clients.pop(user, None)

def private_msg_udp(s: socket.socket, sender: str, target: str, msg: str):
    """Private message with graceful handling for server and clients."""
    global _server_name
    m = format_msg(sender, target, msg, private=True)

    # target is the server
    if target == _server_name:
        # echo back to sender (client) and show on server console
        if sender in udp_clients:
            _safe_sendto(s, m, udp_clients.get(sender))
        print(m)
        return

    # target is a client
    if target in udp_clients:
        # deliver to target
        _safe_sendto(s, m, udp_clients.get(target))
        # echo to sender if sender is a client
        if sender in udp_clients:
            _safe_sendto(s, m, udp_clients.get(sender))
        else:
            # sender is server console — show on server side
            print(m)
        return

    # target not found — inform sender appropriately
    not_found = f"User '{target}' not found."
    if sender in udp_clients:
        _system_to(s, udp_clients.get(sender), not_found)
    else:
        # sender is server console
        print(f"[System] {not_found}")

# ====== Server console thread ======
def server_chat_input_udp(s: socket.socket, name: str):
    """Server-side console loop: never crashes, never exits the main server loop."""
    while True:
        try:
            msg = input().strip()
        except EOFError:
            # treat as exit request
            msg = "exit"
        except Exception:
            print("[System] Input error. Try again.")
            continue

        if not msg:
            print("[System] Cannot send blank message.")
            continue

        if msg.lower() == "exit":
            print("🚪 UDP server stopping. Returning to menu...")
            try:
                s.close()
            except Exception:
                pass
            udp_clients.clear()
            return

        if msg == "/who":
            users = ", ".join(udp_clients.keys()) or "(no users)"
            print(f"[System] Online: {users}")
            continue

        if msg.startswith("@"):
            parts = msg.split(" ", 1)
            if len(parts) != 2 or not parts[0][1:]:
                print("[System] Usage: @username message")
                continue
            target, text = parts[0][1:], parts[1].strip()
            if not text:
                print("[System] Usage: @username message")
                continue
            private_msg_udp(s, name, target, text)
            continue

        # public broadcast from server
        broadcast_udp(s, format_msg(name, "All", msg), sender=name)

# ====== Server main ======
def run_udp_server():
    """Start UDP server. Robust parsing; no duplicate join/leave logs."""
    global _server_name
    _server_name = input("Enter server name: ").strip() or "Server"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", UDP_PORT))
    except Exception:
        print(f"[System] Failed to bind UDP port {UDP_PORT}. Is it already in use?")
        return

    print(f"{timestamp()} [{_server_name}] UDP server running on port {UDP_PORT}")

    # console thread
    threading.Thread(target=server_chat_input_udp, args=(s, _server_name), daemon=True).start()

    try:
        while True:
            try:
                data, addr = s.recvfrom(BUFFER)
            except OSError:
                # socket closed by console thread -> exit cleanly
                break
            except Exception:
                # transient receive issue; keep server alive
                continue

            msg = (data.decode(errors="ignore") or "").strip()
            if not msg:
                _system_to(s, addr, "Cannot send blank message.")
                continue

            # Expect "user:payload"
            if ":" not in msg:
                _system_to(s, addr, "Invalid message format. Use 'username:message'")
                continue

            user, text = msg.split(":", 1)
            user = user.strip()
            text = text.strip()

            if not user:
                _system_to(s, addr, "Username cannot be blank.")
                continue

            # register/update address
            is_new_user = user not in udp_clients
            udp_clients[user] = addr

            # handle "joined" (no duplicate prints)
            if text.lower() == "joined":
                if is_new_user:
                    join_msg = format_msg("System", "All", f"{user} joined the chat.")
                    broadcast_udp(s, join_msg)  # prints once internally
                continue

            # handle exit
            if text.lower() == "exit":
                if user in udp_clients:
                    leave_msg = format_msg("System", "All", f"{user} left the chat.")
                    broadcast_udp(s, leave_msg)  # prints once internally
                    udp_clients.pop(user, None)
                _system_to(s, addr, "You left the chat.")
                continue

            # handle /who
            if text == "/who":
                users = ", ".join(udp_clients.keys()) or "(no users)"
                _system_to(s, addr, f"Online: {users}")
                continue

            # handle private
            if text.startswith("@"):
                parts = text.split(" ", 1)
                if len(parts) != 2 or not parts[0][1:]:
                    _system_to(s, addr, "Usage: @username message")
                    continue
                target, pm = parts[0][1:], parts[1].strip()
                if not pm:
                    _system_to(s, addr, "Usage: @username message")
                    continue
                private_msg_udp(s, user, target, pm)
                continue

            # public broadcast
            broadcast_udp(s, format_msg(user, "All", text), sender=user)

    except KeyboardInterrupt:
        # graceful stop
        pass
    finally:
        print("🚪 UDP server stopping. Returning to menu...")
        try:
            s.close()
        except Exception:
            pass
        udp_clients.clear()

# ====== Client receive thread ======
def recv_udp(sock: socket.socket):
    while True:
        try:
            data, _ = sock.recvfrom(BUFFER)
            if not data:
                continue
            print("\n" + data.decode(errors="ignore").strip())
        except OSError:
            # socket closed
            break
        except Exception:
            # transient receive issue — ignore
            continue

# ====== Client main ======
def udp_client(ip: str):
    """UDP client with connection sanity check and clean errors."""
    alias = input("Enter username: ").strip()
    if not alias:
        print("[System] Invalid username.")
        return

    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Try to 'handshake': send joined, then /who and wait briefly for any reply
    try:
        c.settimeout(2.0)
        c.sendto(f"{alias}:joined".encode(), (ip, UDP_PORT))
        c.sendto(f"{alias}:/who".encode(), (ip, UDP_PORT))
        try:
            _ = c.recvfrom(BUFFER)  # any response is fine
        except socket.timeout:
            print("[System] Could not reach server. Check IP/port or start the server.")
            c.close()
            return
        finally:
            c.settimeout(None)
    except Exception:
        print("[System] Could not connect to server. Check IP/port or start the server.")
        c.close()
        return

    print("\nCommands:")
    print("  /who          - List online users")
    print(f"  @{_server_name} msg  - Private message to server (use 'Server' if unsure)")
    print("  @name msg     - Private message to a user")
    print("  exit          - Leave chat\n")

    # start receiver
    threading.Thread(target=recv_udp, args=(c,), daemon=True).start()

    while True:
        try:
            msg = input().strip()
        except EOFError:
            msg = "exit"
        except Exception:
            print("[System] Input error. Try again.")
            continue

        if not msg:
            print("[System] Cannot send blank message.")
            continue

        # send and handle local exit
        try:
            c.sendto(f"{alias}:{msg}".encode(), (ip, UDP_PORT))
        except Exception:
            print("[System] Failed to send. Server may be unreachable.")
            continue

        if msg.lower() == "exit":
            break

    try:
        c.close()
    except Exception:
        pass
    print("[System] Disconnected from server.")
