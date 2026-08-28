"""
SOCKS5 implementation that supports CONNECT, BIND, UDP ASSOCIATE, but not
authentication.

SOCKS5 is a clear text proxy protocol with no attempt on encryption,
authentication or whatsoever.

Most commonly used as an interface in a secure context (like localhost).
Most browsers and SDKs support SOCKS5.
"""

from ._src.socks5.main import (
    SOCKS5ServerNode,
    SOCKS5ClientNode
)
