from ipaddress import IPv4Address, IPv6Address

from .sdk import *

def SOCKS5Node(server: tuple[str | IPv4Address | IPv6Address, int] | None = None) -> Node:
    """
    SOCKS5 node. Only supports `CONNECT`; Does not support authentication.

    When provided `(host, port)`, the node is in client mode:
    - Reads the proxied session from one upstream.
    - Initiates the SOCKS5 connection with the remote server through one downstream.

    When provided `None`, the node is in server mode:
    - Accepts one upstream SOCKS5 client request.
    - Sends the proxied session to one downstream.

    The host of an inbound SOCKS5 request is faithfully translated into the
    session host without bothering DNS.
    """
