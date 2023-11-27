import socket


def determine_ipv6_address():
    """
    Returns the executing machine's (host) IPv6 for the
    network interface in use.

    @note: This is used for covert file transfer using IPv6 headers
           and fields.

    @return: ipv6_address
        The IPv6 address of the host
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    try:
        # Connect to an IPv6 server, establish connection
        s.connect(('ipv6.google.com', 80))

        # Extract socket information (host-side) for own IPv6 addr.
        ipv6_address = s.getsockname()[0]
        port = s.getsockname()[1]
        s.close()

        return ipv6_address, port

    except socket.error:
        print("[+] ERROR: Unable to determine your IPv6 address!")
        s.close()
        return None, None
