"""
Encrypted Chat App - Client
----------------------------
- Connects to server over TCP
- Encrypts every outgoing message with AES-CBC (fresh random IV each time)
- Decrypts every incoming message
- Runs a background thread to receive messages while you type
"""

import socket
import threading
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ---------------- CONFIG ----------------
SERVER_HOST = "127.0.0.1"   # change to server's IP if connecting remotely
SERVER_PORT = 5555
PSK = b"0123456789abcdef"   # MUST match the server's key exactly


# ---------------- AES HELPERS ----------------
def encrypt_message(plaintext: str, key: bytes) -> str:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct_bytes).decode()


def decrypt_message(token: str, key: bytes) -> str:
    raw = base64.b64decode(token)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


# ---------------- RECEIVE THREAD ----------------
def receive_messages(sock):
    buffer = ""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[!] Disconnected from server.")
                break
            buffer += data.decode()
            while "\n" in buffer:
                token, buffer = buffer.split("\n", 1)
                if not token.strip():
                    continue
                try:
                    plaintext = decrypt_message(token, PSK)
                    print(f"\n[peer]: {plaintext}\nYou: ", end="", flush=True)
                except Exception as e:
                    print(f"\n[!] Failed to decrypt incoming message: {e}")
        except (ConnectionResetError, OSError):
            break


# ---------------- MAIN ----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    print(f"[*] Connected to server {SERVER_HOST}:{SERVER_PORT}")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input("You: ")
            if msg.strip().lower() in ("/quit", "/exit"):
                break
            token = encrypt_message(msg, PSK)
            sock.sendall((token + "\n").encode())
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    main()
