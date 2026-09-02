"""
SOCKS5 implementation that only supports CONNECT; Does not support authentication.

SOCKS5 is a clear text proxy protocol with no attempt on encryption,
authentication or whatsoever.
"""

# ruff: noqa: F401

from ._src.socks5 import SOCKS5ClientNode, SOCKS5ServerNode
