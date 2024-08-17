import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# 解决文件名编码问题
# 数据完整性问题

SERVER_FOLDER = "Server"

USER_DATABASE = {
    "admin": {"password": hashlib.sha256(b"adminpass").hexdigest(), "role": "admin"},
    "user": {"password": hashlib.sha256(b"userpass").hexdigest(), "role": "user"},
}

def list_files():
    files = os.listdir(SERVER_FOLDER)
    return [f for f in files if f != ".DS_Store"]

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

def authenticate(conn):
    credentials = conn.recv(1024).decode().split(":")
    if len(credentials) == 2:
        username, password_hash = credentials
        if username in USER_DATABASE and USER_DATABASE[username]["password"] == password_hash:
            conn.sendall(f"AUTH_SUCCESS:{USER_DATABASE[username]['role']}".encode())
            return USER_DATABASE[username]["role"]
    conn.sendall(b"AUTH_FAIL")
    return None

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    role = authenticate(conn)
    if not role:
        print(f"Authentication failed for {addr}")
        conn.close()
        return

    while True:
        try:
            request = conn.recv(1024).decode(errors='ignore').strip()
        except UnicodeDecodeError:
            print("Received invalid UTF-8 data")
            conn.sendall(b"Invalid data format")
            continue

        if request == "1":
            files = list_files()
            conn.sendall("\n".join(files).encode())
        elif request.startswith("DOWNLOAD"):
            filename = request.split()[1].replace("%20", " ")
            filepath = os.path.join(SERVER_FOLDER, filename)
            if os.path.exists(filepath):
                key = os.urandom(16)
                iv = os.urandom(16)
                encrypted_data = encrypt_file(filepath, key, iv)
                data_length = len(encrypted_data)
                conn.sendall(data_length.to_bytes(16, 'big') + key + iv)

                # Use a loop to send the encrypted data in chunks
                chunk_size = 4096
                for i in range(0, data_length, chunk_size):
                    conn.sendall(encrypted_data[i:i + chunk_size])
            else:
                conn.sendall(b"File not found")
        elif request.startswith("UPLOAD") and role == "admin":
            filename = request.split()[1].replace("%20", " ")
            length_data = conn.recv(16)
            file_length = int.from_bytes(length_data, 'big')
            key_iv_data = conn.recv(32)
            key, iv = key_iv_data[:16], key_iv_data[16:32]

            # Receive the file data in chunks
            file_data = b''
            while len(file_data) < file_length:
                file_data += conn.recv(min(4096, file_length - len(file_data)))

            if len(file_data) != file_length:
                print(f"Error: Received file data length {len(file_data)} does not match expected {file_length}")
                conn.sendall(b"File upload failed")
                return

            decrypted_data = decrypt_file(file_data, key, iv)
            with open(os.path.join(SERVER_FOLDER, filename), 'wb') as f:
                f.write(decrypted_data)
            print(f"Uploaded {filename}")
        elif request == "exit":
            break
    conn.close()

def start_server(host="0.0.0.0", port=65432):
    if not os.path.exists(SERVER_FOLDER):
        os.makedirs(SERVER_FOLDER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Server listening on port", port)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()