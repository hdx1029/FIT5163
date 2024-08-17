import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from urllib.parse import quote, unquote

CLIENT_FOLDER = "Client"

def list_files():
    files = os.listdir(CLIENT_FOLDER)
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

def start_client(server_ip="127.0.0.1", server_port=65432):
    if not os.path.exists(CLIENT_FOLDER):
        os.makedirs(CLIENT_FOLDER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))

        # Authentication
        username = input("Enter username: ")
        password = input("Enter password: ")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        s.sendall(f"{username}:{password_hash}".encode())
        auth_response = s.recv(1024).decode()
        if auth_response.startswith("AUTH_FAIL"):
            print("Authentication failed.")
            return

        role = auth_response.split(":")[1]

        while True:
            if role == "admin":
                choice = input("1. Download\n2. Upload\n3. Exit\nChoose an option: ")
            else:
                choice = input("1. Download\n3. Exit\nChoose an option: ")

            if choice == "1":
                s.sendall(b"1")
                files = s.recv(1024).decode().split("\n")
                for file in files:
                    print(file)
                filename = input("Enter the filename to download: ").strip()
                filename_encoded = quote(filename)
                s.sendall(f"DOWNLOAD {filename_encoded}".encode())
                data_length = int.from_bytes(s.recv(16), 'big')
                data = b''
                while len(data) < data_length + 32:
                    chunk = s.recv(min(4096, data_length + 32 - len(data)))
                    if not chunk:
                        break
                    data += chunk

                if data.startswith(b"File not found"):
                    print("File not found on server.")
                else:
                    key, iv, encrypted_data = data[:16], data[16:32], data[32:]
                    decrypted_data = decrypt_file(encrypted_data, key, iv)
                    with open(os.path.join(CLIENT_FOLDER, filename), 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Downloaded {filename}")
            elif choice == "2" and role == "admin":
                files = list_files()
                for file in files:
                    print(file)
                filename = input("Enter the filename to upload: ").strip()
                filename_encoded = quote(filename)
                filepath = os.path.join(CLIENT_FOLDER, filename)
                if os.path.exists(filepath):
                    key = os.urandom(16)
                    iv = os.urandom(16)
                    encrypted_data = encrypt_file(filepath, key, iv)
                    file_length = len(encrypted_data)
                    s.sendall(f"UPLOAD {filename_encoded}".encode())
                    s.sendall(file_length.to_bytes(16, 'big') + key + iv + encrypted_data)
                    print(f"Uploaded {filename}")
                else:
                    print("File not found in client folder.")
            elif choice == "3":
                s.sendall(b"exit")
                print("Exiting...")
                break
            else:
                print("Invalid option. Please choose again.")

if __name__ == "__main__":
    start_client()