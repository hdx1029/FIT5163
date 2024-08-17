import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

SERVER_FOLDER = "Server"

def list_files():
    return os.listdir(SERVER_FOLDER)

def encrypt_file(filepath, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def decrypt_file(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    while True:
        request = conn.recv(1024).decode()
        if request == "1":
            files = list_files()
            conn.sendall("\n".join(files).encode())
        elif request.startswith("DOWNLOAD"):
            filename = request.split()[1]
            filepath = os.path.join(SERVER_FOLDER, filename)
            if os.path.exists(filepath):
                key = os.urandom(16)
                iv = os.urandom(16)
                encrypted_data = encrypt_file(filepath, key, iv)
                conn.sendall(key + iv + encrypted_data)
            else:
                conn.sendall(b"File not found")
        elif request.startswith("UPLOAD"):
            filename = request.split()[1]
            data = conn.recv(4096)
            key, iv, file_data = data[:16], data[16:32], data[32:]
            decrypted_data = decrypt_file(file_data, key, iv)
            with open(os.path.join(SERVER_FOLDER, filename), 'wb') as f:
                f.write(decrypted_data)
            print(f"Uploaded {filename}")
        elif request == "exit":
            break
    conn.close()

def start_server(host="0.0.0.0", port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Server listening on port", port)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()