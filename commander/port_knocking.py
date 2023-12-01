import re
import time

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff, send


def __valid_port_sequence_pattern(port_sequence: str):
    pattern = r'^\d+(,\s*\d+)*$'
    return bool(re.match(pattern, port_sequence))


def __convert_port_sequence_list(port_sequence: list):
    formatted_port_sequence = []

    for port_num in port_sequence:
        formatted_port_num = int(port_num)

        if 0 <= formatted_port_num > 65535:
            raise ValueError("An invalid port number was provided (cannot be less than or equal "
                             "to 0 or greater than 65535)!")

        formatted_port_sequence.append(formatted_port_num)

    return formatted_port_sequence


def __get_port_sequence_prompt():
    """
    Prompts and returns the user's port sequence.

    @return port_sequence:
        A list of port numbers
    """
    while True:
        try:
            # a) Get port sequence
            port_sequence = input("[+] Enter a port sequence to connect to target/victim in the "
                                  "following format (ex: 22, 80, 8888): ")

            # b) Check if the port sequence is valid
            if __valid_port_sequence_pattern(port_sequence):
                try:
                    return __convert_port_sequence_list(port_sequence.split(","))
                except ValueError as e:
                    print("[+] INVALID PORT NUMBER PROVIDED: {}".format(e))
            else:
                print("[+] GET PORT SEQUENCE ERROR: An invalid port sequence format was provided!")
                print("[+] Please try again...")
        except ValueError as e:
            print("[+] GET PORT SEQUENCE ERROR: An error has occurred - {}".format(e))


def perform_port_knocking(victim_ip: str, victim_port: int):
    """
    Performs port knocking by sending raw packets
    to specific ports of the victim/target.

    @param victim_ip:
        The victim/target's IP address to connect

    @param victim_port:
        The victim/target's port number to connect
        (Used for sniffing response)

    @return: None
    """
    while True:
        # a) Get port sequence from user
        port_sequence = __get_port_sequence_prompt()

        # a) Craft and send raw packets in sequence
        for port_num in port_sequence:
            packet = IP(dst=victim_ip) / TCP(dport=port_num)
            send(packet, verbose=0)
            time.sleep(1)  # To allow victim to buffer
            print("[+] Packet successfully sent to port {} on victim/target!".format(port_num))

        # b) Wait for a response packet
        print("[+] Now awaiting response from victim/target...")
        packet_list = sniff(filter="src host {} and src port {}".format(victim_ip, victim_port),
                            count=1, timeout=10)

        # c) Check if timeout or incorrect sequence
        if len(packet_list) == 0:
            print("[+] PORT KNOCKING FAILED: An incorrect port sequence was provided and timeout has occurred!")
            print("[+] Please try again...")
        # Otherwise, extract the message
        else:
            for packet in packet_list:  # List length == 1
                if TCP in packet and packet[TCP].payload:
                    response = packet[TCP].payload.load.decode('utf-8', 'ignore')
                    if response == "ACCEPTED":
                        print("[+] PORT KNOCKING SUCCESS: Now connecting to victim/target...")
                        return None
                    else:
                        print("[+] PORT KNOCKING FAILED: An incorrect port sequence was provided!")
                        print("[+] Please try again...")
