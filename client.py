import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from urllib.parse import quote, unquote

# Folder where client files are stored
CLIENT_FOLDER = "Client"


# Function to list all files in the client folder
def list_files():
    files = os.listdir(CLIENT_FOLDER)
    return [f for f in files if f != ".DS_Store"]


# Function to encrypt a file using AES
def encrypt_file(filepath, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data


# Function to decrypt AES encrypted data
def decrypt_file(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data


# Function to start the client and connect to the server
def start_client(server_ip="127.0.0.1", server_port=65432):
    # Create client folder if it doesn't exist
    if not os.path.exists(CLIENT_FOLDER):
        os.makedirs(CLIENT_FOLDER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))  # Connect to the server

        # Authentication process
        username = input("Enter username: ")
        password = input("Enter password: ")
        # Hash the password before sending
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        s.sendall(f"{username}:{password_hash}".encode())
        auth_response = s.recv(1024).decode()
        if auth_response.startswith("AUTH_FAIL"):
            print("Authentication failed.")
            return

        role = auth_response.split(":")[1]  # Get the role from the server's response

        while True:
            if role == "admin":
                # Admin users can choose to download, upload, or exit
                choice = input("1. Download\n2. Upload\n3. Exit\nChoose an option: ")
            else:
                # Regular users can only download or exit
                choice = input("1. Download\n3. Exit\nChoose an option: ")

            if choice == "1":
                s.sendall(b"1")  # Request to list files on the server
                files = s.recv(1024).decode().split("\n")  # Receive and display file list
                for file in files:
                    print(file)
                filename = input("Enter the filename to download: ").strip()
                filename_encoded = quote(filename)  # Encode the filename for URL safety
                s.sendall(f"DOWNLOAD {filename_encoded}".encode())

                # Receive the file data from the server
                data_length = int.from_bytes(s.recv(16), 'big')
                data = b''
                while len(data) < data_length + 32:  # +32 for key and IV
                    chunk = s.recv(min(4096, data_length + 32 - len(data)))
                    if not chunk:
                        break
                    data += chunk

                if data.startswith(b"File not found"):
                    print("File not found on server.")
                else:
                    # Extract key, IV, and encrypted data
                    key, iv, encrypted_data = data[:16], data[16:32], data[32:]
                    decrypted_data = decrypt_file(encrypted_data, key, iv)  # Decrypt the data
                    # Save the downloaded file
                    with open(os.path.join(CLIENT_FOLDER, filename), 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Downloaded {filename}")

            elif choice == "2" and role == "admin":
                # Handle file upload request (only for admin users)
                files = list_files()
                for file in files:
                    print(file)
                filename = input("Enter the filename to upload: ").strip()
                filename_encoded = quote(filename)  # Encode the filename for URL safety
                filepath = os.path.join(CLIENT_FOLDER, filename)
                if os.path.exists(filepath):
                    key = os.urandom(16)  # Generate a random key
                    iv = os.urandom(16)  # Generate a random IV
                    encrypted_data = encrypt_file(filepath, key, iv)  # Encrypt the file
                    file_length = len(encrypted_data)
                    # Send upload request along with file length, key, IV, and encrypted data
                    s.sendall(f"UPLOAD {filename_encoded}".encode())
                    s.sendall(file_length.to_bytes(16, 'big') + key + iv + encrypted_data)
                    print(f"Uploaded {filename}")
                else:
                    print("File not found in client folder.")

            elif choice == "3":
                s.sendall(b"exit")  # Send exit request to the server
                print("Exiting...")
                break

            else:
                print("Invalid option. Please choose again.")


# Entry point of the script
if __name__ == "__main__":
    start_client()