from ipaddress import IPv4Address, IPv6Address

from .sdk import *

def SOCKS5Node(server: tuple[str | IPv4Address | IPv6Address, int] | None = None) -> Node:
    """
    SOCKS5 node. Only supports `CONNECT`; Does not support authentication.
    
    When constructed without a server address, the node is a SOCKS5 server:
    - Accepts one upstream SOCKS5 client requests.
    - Sends proxied session to one downstream.
    
    When constructed with a SOCKS5 server address, the node is a SOCKS5 client:
    - Reads proxied session from one upstream.
    - Initiates SOCKS5 connection with remote server through one downstream.
    
    The host of an inbound SOCKS5 request is faithfully translated into the
    session host without bothering DNS.
    """
