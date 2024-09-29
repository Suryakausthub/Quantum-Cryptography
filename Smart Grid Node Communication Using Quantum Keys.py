import socket
import threading

# Function to handle secure message transmission between nodes
def handle_node_communication(connection, address, encryption_key):
    print(f"Connection from {address} has been established.")

    # Receiving and decrypting message from a node
    encrypted_message = connection.recv(1024)
    decrypted_message = encryption_key.decrypt(encrypted_message)
    print(f"Received decrypted message from node {address}: {decrypted_message.decode('utf-8')}")

    # Sending acknowledgment
    ack_message = "Message received securely.".encode('utf-8')
    encrypted_ack = encryption_key.encrypt(ack_message)
    connection.send(encrypted_ack)

    connection.close()

# Simulate a smart grid communication server
def smart_grid_node_server(encryption_key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 9999))
    server_socket.listen(5)
    print("Smart Grid Node Server listening for connections...")

    while True:
        connection, address = server_socket.accept()
        thread = threading.Thread(target=handle_node_communication, args=(connection, address, encryption_key))
        thread.start()

# Simulate a node sending secure communication
def node_client_send(encryption_key, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 9999))

    # Encrypt and send message
    encrypted_message = encryption_key.encrypt(message.encode('utf-8'))
    client_socket.send(encrypted_message)

    # Receive acknowledgment from the server
    encrypted_ack = client_socket.recv(1024)
    decrypted_ack = encryption_key.decrypt(encrypted_ack)
    print(f"Acknowledgment received: {decrypted_ack.decode('utf-8')}")

    client_socket.close()

