"""
RFMP client - Setup and Operation Phase
"""

import socket
import os
import base64
from Crypto.Cipher import AES  # pip install pycryptodome

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
    # turns raw bytes (like an RSA key, or file data) into safe text
    # with no commas or newlines in it, so it can't break packet framing
    encoded = base64.b64encode(data)
    return encoded.decode()


def decode_bytes(text):
    # turns the text string back into raw bytes
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
    # Bug 1: picks the cipher that was agreed on during setup, then
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


def main():
    answer = input("Require secure communication? (y/n): ")
    secure = False
    if answer == "y":
        secure = True

    algorithm = "AES"  # default, only matters if secure is True

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((HOST, PORT))

    # 1. Sending the Start-Packet
    if secure:
        send_packet(client_sock, "SS,RFMP,v1.0,1")
    else:
        send_packet(client_sock, "SS,RFMP,v1.0,0")

    # 2. Confirming the Connection-Packet
    packet = recv_packet(client_sock)
    parts = packet.split(",")
    packet_type = parts[0]

    if packet_type != "CC":
        print("Unexpected reply, closing")
        client_sock.close()
        return

    if secure:
        server_pub_text = parts[1]
        server_pub_bytes = decode_bytes(server_pub_text)
        server_pub = rsa.PublicKey.load_pkcs1(server_pub_bytes)

        client_pub, client_priv = rsa.newkeys(2048)
        session_key = os.urandom(16)

        choice_text = input("Choose encryption algorithm (AES/Caesar): ")
        if choice_text == "Caesar":
            algorithm = "Caesar"
        else:
            algorithm = "AES"

        enc_session_key = rsa.encrypt(session_key, server_pub)
        enc_session_key_text = encode_bytes(enc_session_key)

        client_pub_text = encode_bytes(client_pub.save_pkcs1())
        username = "client1"
        credentials = username + ":" + client_pub_text

        packet_to_send = "EC," + algorithm + "," + enc_session_key_text + "," + credentials
        send_packet(client_sock, packet_to_send)

        print("Secure setup finished")
    else:
        print("Unsecured setup finished")

    # Operation Phase
    while True:
        print("\n--- RFMP Menu ---")
        print("1. mkdir")
        print("2. cd")
        print("3. rmdir")
        print("4. del")
        print("5. ren")
        print("6. openRead")
        print("7. openWrite")
        print("8. exit")
        print("9. dir")
        print("10. whoami")
        print("11. hostname")
        print("12. ipconfig")
        print("13. echo")

        choice = input("Enter your choice: ")

        if choice == "8":
            send_packet(client_sock, "End")
            break

        if choice == "1":
            command = input("Enter folder name: ")
            packet = "CM,prompt,mkdir " + command

        elif choice == "2":
            command = input("Enter folder path: ")
            packet = "CM,prompt,cd " + command

        elif choice == "3":
            command = input("Enter folder name: ")
            packet = "CM,prompt,rmdir " + command

        elif choice == "4":
            command = input("Enter file name: ")
            packet = "CM,prompt,del " + command

        elif choice == "5":
            command = input("Enter old name and new name: ")
            packet = "CM,prompt,ren " + command

        elif choice == "6":
            filename = input("Enter file name: ")
            packet = "CM,openRead," + filename

        elif choice == "7":
            filename = input("Enter file name: ")
            packet = "CM,openWrite," + filename

        elif choice == "9":
            packet = "CM,prompt,dir"

        elif choice == "10":
            packet = "CM,prompt,whoami"

        elif choice == "11":
            packet = "CM,prompt,hostname"

        elif choice == "12":
            packet = "CM,prompt,ipconfig"

        elif choice == "13":
            command = input("Enter message: ")
            packet = "CM,prompt,echo " + command

        else:
            print("Invalid choice")
            continue

        send_packet(client_sock, packet)

        reply = recv_packet(client_sock)

        if reply.startswith("DP,"):
            received_data = reply.split(",", 1)[1]

            if secure:
                data = decrypt_data(received_data, session_key, algorithm)
            else:
                # undo the base64-safe wrapping the server always applies now
                data = decode_bytes(received_data).decode()

            print("File contents:")
            print(data)

        elif reply.startswith("EE,"):
            error_parts = reply.split(",", 2)

            error_code = error_parts[1]
            error_message = error_parts[2]

            print("Error code:", error_code)
            print("Error:", error_message)

        else:
            print("Server:", reply)

        # only sends the file data if the server actually opened the file
        if choice == "7" and reply.startswith("SC,"):
            data = input("Enter data to write: ")

            if secure:
                encrypted_data = encrypt_data(data, session_key, algorithm)
                send_packet(client_sock, "DP," + encrypted_data)
            else:
                payload = encode_bytes(data.encode())
                send_packet(client_sock, "DP," + payload)

            reply = recv_packet(client_sock)
            print("Server:", reply)

    client_sock.close()


main()