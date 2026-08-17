# Encrypted Chat App

A simple client/server chat application in Python where all messages are
encrypted with **AES (CBC mode)** before being sent over the network.

## Features

- TCP socket communication (`socket` module)
- AES-CBC encryption/decryption of every message (`pycryptodome`)
- Fresh random IV generated per message (never reused with the same key)
- Pre-shared key (PSK) based symmetric encryption
- Multi-client support using `threading` (basic concurrency)
- Server-side message logging with timestamps (`chat_log.txt`)
- Basic error handling for disconnects and failed decryption

## Project Structure

```
encrypted-chat-app/
├── server.py         # TCP server, handles multiple clients, decrypts + logs + broadcasts
├── client.py          # TCP client, encrypts outgoing messages, decrypts incoming
├── requirements.txt   # Python dependencies
└── README.md
```

## Requirements

- Python 3.8+
- pycryptodome

## Setup

```bash
git clone https://github.com/hassaansec/encrypted-chat-app.git
cd encrypted-chat-app
pip install -r requirements.txt
```

## Usage

**1. Start the server** (in one terminal):

```bash
python3 server.py
```

**2. Start one or more clients** (in separate terminals):

```bash
python3 client.py
```

Type messages and press Enter to send. Type `/quit` or `/exit` to disconnect.

All decrypted messages are logged on the server side to `chat_log.txt` with
a timestamp and sender address.

## How the encryption works

1. Both server and client share a pre-set AES key (`PSK` in the config
   section of each file — must match on both sides).
2. Before sending, the client generates a **random 16-byte IV**, encrypts
   the message with `AES-CBC`, and sends `base64(iv + ciphertext)`.
3. The receiver splits the IV back off, decrypts, and unpads the plaintext.

## Known limitations / next steps

- The key is currently **hardcoded** as a pre-shared key. This is fine for
  a demo but not secure for real use — a production version should use a
  proper key-exchange protocol (e.g. Diffie-Hellman) so the key is never
  transmitted or stored in source code.
- No authentication — any client that connects and knows the PSK can join.
- No TLS — this project demonstrates *application-layer* AES encryption,
  not transport security.

## License

MIT
