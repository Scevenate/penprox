# Script of a basic SOCKS5 server.
# A second hop is introduced for fun.

from ipaddress import IPv4Address
from sys import stderr
from threading import Thread

from penprox import *
from penprox.socks5 import *

set_logger(stderr, LogLevel.DEBUG)

hop1 = TCPNode((IPv4Address("127.0.0.1"), 1080)) >> \
SOCKS5Node() >> \
SOCKS5Node((IPv4Address("127.0.0.1"), 1081)) >> \
TCPNode()

hop2 = TCPNode((IPv4Address("127.0.0.1"), 1081)) >> \
SOCKS5Node() >> \
DNSNode() >> \
TCPNode()

thread1 = Thread(target=hop1.spawn)
thread2 = Thread(target=hop2.spawn)

thread1.start()
thread2.start()

thread1.join()
thread2.join()
