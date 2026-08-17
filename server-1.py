"""
Encrypted Chat App - Server
----------------------------
- TCP server using sockets + threading for multiple clients
- AES-CBC encryption/decryption using a pre-shared key
- Random IV generated per message (sent along with ciphertext)
- Logs all decrypted messages with timestamp to chat_log.txt
"""

import socket
import threading
import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ---------------- CONFIG ----------------
HOST = "0.0.0.0"
PORT = 5555
# Pre-shared key - must be 16, 24, or 32 bytes for AES-128/192/256
# In production this should be exchanged securely (e.g. Diffie-Hellman), not hardcoded.
PSK = b"0123456789abcdef"  # 16 bytes -> AES-128
LOG_FILE = "chat_log.txt"

clients = []          # list of connected client sockets
clients_lock = threading.Lock()


# ---------------- AES HELPERS ----------------
def encrypt_message(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext with AES-CBC using a fresh random IV each time.
    Returns base64(iv + ciphertext) as a string for easy transport."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()


def decrypt_message(token: str, key: bytes) -> str:
    """Decrypt base64(iv + ciphertext) back to plaintext."""
    raw = base64.b64decode(token)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


def log_message(sender_addr, message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {sender_addr} -> {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    print(line.strip())


# ---------------- CLIENT HANDLER ----------------
def broadcast(token: str, sender_socket):
    """Send an already-encrypted token to all clients except the sender."""
    with clients_lock:
        for c in clients:
            if c is not sender_socket:
                try:
                    c.sendall((token + "\n").encode())
                except Exception:
                    pass


def handle_client(client_socket, addr):
    print(f"[+] New connection: {addr}")
    with clients_lock:
        clients.append(client_socket)

    buffer = ""
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            buffer += data.decode()

            # messages are newline-delimited
            while "\n" in buffer:
                token, buffer = buffer.split("\n", 1)
                if not token.strip():
                    continue
                try:
                    plaintext = decrypt_message(token, PSK)
                except Exception as e:
                    print(f"[!] Failed to decrypt message from {addr}: {e}")
                    continue

                log_message(addr, plaintext)
                # re-broadcast the same encrypted token to other clients
                broadcast(token, client_socket)
    except ConnectionResetError:
        pass
    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()
        print(f"[-] Disconnected: {addr}")


# ---------------- MAIN ----------------
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
    finally:
        server.close()


if __name__ == "__main__":
    main()
