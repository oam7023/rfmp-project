"""
RFMP client - Setup Phase.
"""

import socket
import os
import base64

import rsa  # pip install rsa

HOST = "127.0.0.1"
PORT = 5050

def send_packet(sock, text):
    # adds a newline so the other side knows where the packet ends
    message = text + "\n"
    sock.send(message.encode())

def recv_packet(sock):
    # reads one byte at a time until we hit the newline character
    text = ""
    while True:
        byte = sock.recv(1)
        if byte == b"" or byte == b"\n":
            break
        text = text + byte.decode()
    return text

def encode_bytes(data):
    # turns raw bytes (like an RSA key) into a safe text string
    encoded = base64.b64encode(data)
    return encoded.decode()

def decode_bytes(text):
    # turns the text string back into raw bytes
    return base64.b64decode(text.encode())