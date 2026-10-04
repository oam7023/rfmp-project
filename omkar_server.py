"""
RFMP server - Setup and Operation Phase
"""

import socket
import threading
import base64
import os
import subprocess

from Crypto.Cipher import AES  # pip install pycryptodome
import rsa  # pip install rsa

HOST = "0.0.0.0"
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
    # turns raw bytes (like an RSA key, or file data) into safe text
    # with no commas or newlines in it, so it can't break packet framing
    encoded = base64.b64encode(data)
    return encoded.decode()


def decode_bytes(text):
    # turn the text string back into raw bytes
    return base64.b64decode(text.encode())


def caesar_encrypt(text, key):
    # shift each character's code by an amount based on the session key
    shift = key[0]
    result = ""
    for char in text:
        new_code = (ord(char) + shift) % 256
        result = result + chr(new_code)
    return result


def caesar_decrypt(text, key):
    # reverse the shift using the same byte of the session key
    shift = key[0]
    result = ""
    for char in text:
        new_code = (ord(char) - shift) % 256
        result = result + chr(new_code)
    return result


def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    encrypted = cipher.encrypt(text.encode())
    data = cipher.nonce + encrypted
    return encode_bytes(data)


def aes_decrypt(text, key):
    data = decode_bytes(text)

    nonce = data[:16]
    encrypted = data[16:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(encrypted)

    return decrypted.decode()


def encrypt_data(text, key, algorithm):
    # picks the cipher the client asked for during setup, then
    # base64-encodes the result so it's always safe to put in a packet
    if algorithm == "Caesar":
        shifted = caesar_encrypt(text, key)
        return encode_bytes(shifted.encode())
    else:
        return aes_encrypt(text, key)


def decrypt_data(text, key, algorithm):
    if algorithm == "Caesar":
        shifted_bytes = decode_bytes(text)
        shifted = shifted_bytes.decode()
        return caesar_decrypt(shifted, key)
    else:
        return aes_decrypt(text, key)


def handle_client(client_sock):
    print("New connection")

    # 1. Getting the Start-Packet: SS,RFMP,secure_flag
    packet = recv_packet(client_sock)
    parts = packet.split(",")
    packet_type = parts[0]
    secure_flag = parts[3]

    if packet_type != "SS":
        print("Bad packet, closing")
        client_sock.close()
        return

    secure = False
    if secure_flag == "1":
        secure = True

    session_key = None
    algorithm = None

    if secure:
        # making an RSA key pair for this connection
        server_pub, server_priv = rsa.newkeys(2048)
        pub_text = encode_bytes(server_pub.save_pkcs1())
        send_packet(client_sock, "CC," + pub_text)

        # 2. Getting the Encryption-Packet: EC,Algorithm,session_key,username:client_pub
        packet = recv_packet(client_sock)
        parts = packet.split(",")
        algorithm = parts[1]
        enc_session_key_text = parts[2]
        credentials = parts[3]

        enc_session_key = decode_bytes(enc_session_key_text)
        session_key = rsa.decrypt(enc_session_key, server_priv)

        print("Algorithm used: " + algorithm)
        print("Session key length: " + str(len(session_key)))
    else:
        send_packet(client_sock, "CC")

    print("Setup phase finished")

    # Operation Phase
    while True:
        packet = recv_packet(client_sock)

        if packet == "":
            break
        if packet == "End":
            break

        parts = packet.split(",", 2)
        packet_type = parts[0]

        if packet_type == "CM":
            command_type = parts[1]
            command = parts[2]

            if command_type == "openRead":
                filename = command

                try:
                    file = open(filename, "r")
                    data = file.read()
                    file.close()

                    if secure:
                        payload = encrypt_data(data, session_key, algorithm)
                    else:
                        # base64-encode even when unsecured, so file content
                        # with commas/newlines in it can't break packet framing
                        payload = encode_bytes(data.encode())

                    send_packet(client_sock, "DP," + payload)

                except Exception:
                    send_packet(client_sock, "EE,4,Cannot read file")

            elif command_type == "openWrite":
                filename = command

                try:
                    file = open(filename, "w")
                    send_packet(client_sock, "SC,File opened for writing")

                    data_packet = recv_packet(client_sock)
                    data_parts = data_packet.split(",", 1)

                    if data_parts[0] == "DP":

                        if secure:
                            data = decrypt_data(data_parts[1], session_key, algorithm)
                        else:
                            data = decode_bytes(data_parts[1]).decode()

                        file.write(data)
                        file.close()

                        send_packet(client_sock, "SC,Data written to file")
                    else:
                        file.close()
                        send_packet(client_sock, "EE,3,Expected data packet")

                except Exception:
                    send_packet(client_sock, "EE,3,Cannot open file")

            elif command_type == "prompt":
                try:

                    if command.startswith("cd "):
                        folder = command[3:].strip()
                        os.chdir(folder)

                        send_packet(client_sock, "SC,Directory changed")

                    else:
                        result = subprocess.run(command, shell=True, capture_output=True, text=True)

                        if result.returncode == 0:
                            output = result.stdout.strip()
                            if output == "":
                                output = "Command executed successfully"
                            # real newlines would break packet framing, so
                            # replace them with a visible separator instead
                            output = output.replace("\r", "")
                            output = output.replace("\n", " | ")
                            send_packet(client_sock, "SC," + output)
                        else:
                            error = result.stderr.strip()
                            if error == "":
                                error = "Command failed"
                            error = error.replace("\r", "")
                            error = error.replace("\n", " | ")
                            send_packet(client_sock, "EE,1," + error)

                except Exception:
                    send_packet(client_sock, "EE,1,Command failed")

        else:
            send_packet(client_sock, "EE,2,Unknown packet")

    client_sock.close()


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen()
    print("Server is listening on port " + str(PORT))

    while True:
        client_sock, addr = server_sock.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock,))
        thread.start()


main()