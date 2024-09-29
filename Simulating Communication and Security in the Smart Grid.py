if __name__ == '__main__':
    # Step 1: Initiate Quantum Key Distribution between two nodes
    encryption_key = initiate_secure_communication()

    # Step 2: Start the Smart Grid Node server
    server_thread = threading.Thread(target=smart_grid_node_server, args=(encryption_key,))
    server_thread.start()

    # Step 3: Simulate a node client sending a secure message
    test_message = "Grid Node 1: Power levels normal."
    node_client_send(encryption_key, test_message)
