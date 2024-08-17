import os
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Folder where server files are stored
SERVER_FOLDER = "Server"

# User database with hashed passwords
USER_DATABASE = {
    "admin": {"password": hashlib.sha256(b"adminpass").hexdigest(), "role": "admin"},
    "user": {"password": hashlib.sha256(b"userpass").hexdigest(), "role": "user"},
}

# Function to list all files in the server folder
def list_files():
    files = os.listdir(SERVER_FOLDER)
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

# Function to authenticate a client using credentials
def authenticate(conn):
    # Receive credentials in the form of "username:password_hash"
    credentials = conn.recv(1024).decode().split(":")
    if len(credentials) == 2:
        username, password_hash = credentials
        # Check if the username exists and the password hash matches
        if username in USER_DATABASE and USER_DATABASE[username]["password"] == password_hash:
            # Send success message with the user's role
            conn.sendall(f"AUTH_SUCCESS:{USER_DATABASE[username]['role']}".encode())
            return USER_DATABASE[username]["role"]
    # Send failure message if authentication fails
    conn.sendall(b"AUTH_FAIL")
    return None

# Function to handle communication with a client
def handle_client(conn, addr):
    print(f"Connected by {addr}")
    role = authenticate(conn)  # Authenticate the client
    if not role:
        print(f"Authentication failed for {addr}")
        conn.close()  # Close connection if authentication fails
        return

    while True:
        try:
            # Receive and decode the client's request
            request = conn.recv(1024).decode(errors='ignore').strip()
        except UnicodeDecodeError:
            print("Received invalid UTF-8 data")
            conn.sendall(b"Invalid data format")
            continue

        if request == "1":
            # List files if the request is "1"
            files = list_files()
            conn.sendall("\n".join(files).encode())
        elif request.startswith("DOWNLOAD"):
            # Handle file download request
            filename = request.split()[1].replace("%20", " ")
            filepath = os.path.join(SERVER_FOLDER, filename)
            if os.path.exists(filepath):
                # Generate key and IV for encryption
                key = os.urandom(16)
                iv = os.urandom(16)
                encrypted_data = encrypt_file(filepath, key, iv)
                data_length = len(encrypted_data)
                # Send the file length, key, and IV to the client
                conn.sendall(data_length.to_bytes(16, 'big') + key + iv)

                # Use a loop to send the encrypted data in chunks
                chunk_size = 4096
                for i in range(0, data_length, chunk_size):
                    conn.sendall(encrypted_data[i:i + chunk_size])
            else:
                conn.sendall(b"File not found")
        elif request.startswith("UPLOAD") and role == "admin":
            # Handle file upload request (only for admin users)
            filename = request.split()[1].replace("%20", " ")
            length_data = conn.recv(16)  # Receive the length of the file
            file_length = int.from_bytes(length_data, 'big')
            key_iv_data = conn.recv(32)  # Receive the key and IV
            key, iv = key_iv_data[:16], key_iv_data[16:32]

            # Receive the file data in chunks
            file_data = b''
            while len(file_data) < file_length:
                file_data += conn.recv(min(4096, file_length - len(file_data)))

            if len(file_data) != file_length:
                print(f"Error: Received file data length {len(file_data)} does not match expected {file_length}")
                conn.sendall(b"File upload failed")
                return

            # Decrypt and save the uploaded file
            decrypted_data = decrypt_file(file_data, key, iv)
            with open(os.path.join(SERVER_FOLDER, filename), 'wb') as f:
                f.write(decrypted_data)
            print(f"Uploaded {filename}")
        elif request == "exit":
            break  # Exit loop if the client sends "exit"
    conn.close()  # Close the connection when done

# Function to start the server
def start_server(host="0.0.0.0", port=65432):
    # Create server folder if it doesn't exist
    if not os.path.exists(SERVER_FOLDER):
        os.makedirs(SERVER_FOLDER)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))  # Bind the server to the specified host and port
        s.listen()  # Start listening for incoming connections
        print("Server listening on port", port)
        while True:
            conn, addr = s.accept()  # Accept a new connection
            # Start a new thread to handle the client
            threading.Thread(target=handle_client, args=(conn, addr)).start()

# Entry point of the script
if __name__ == "__main__":
    start_server()