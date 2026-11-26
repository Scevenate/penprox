import sys
from ipaddress import IPv4Address

from penprox import *

set_logger(sys.stderr, LogLevel.DEBUG)

graph = TCPNode((IPv4Address("127.0.0.1"), 1080)) >> \
    SOCKS5Node((IPv4Address("10.68.0.1"), 1080)) >> \
    TLSNode() >> \
    TLSNode() >> \
    TCPNode()

graph.spawn()
