"""
RFMP server - Setup Phase.
"""

import socket
import threading
import base64
import os

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
    # turns raw bytes (like an RSA key) into a safe text string
    encoded = base64.b64encode(data)
    return encoded.decode()

def decode_bytes(text):
    # turn the text string back into raw bytes
    return base64.b64decode(text.encode())

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

        parts = packet.split(",", 2)
        packet_type = parts[0]

        if packet_type == "CM":
            command_type = parts[1]
            command = parts[2]
            if command_type == "openWrite":
                filename = command

                try:
                    file = open(filename, "w")
                    send_packet(client_sock, "SC,File opened for writing")

                    data_packet = recv_packet(client_sock)

                    data_parts = data_packet.split(",", 1)

                    if data_parts[0] == "DP":
                        data = data_parts[1]
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
                    result = os.system(command)

                    if result == 0:
                        send_packet(client_sock, "SC,Command executed")
                    else:
                        send_packet(client_sock, "EE,1,Command failed")

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