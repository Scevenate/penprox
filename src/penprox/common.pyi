from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from .sdk import *

def TCPNode(address: tuple[IPv4Address | IPv6Address, int] | None = None) -> Node:
    """
    Node for TCP, may listen a port. Doesn't support DNS.
    
    When provided `(ip, port)`, the node is in upstream mode:
    - The node listens to the port.
    - It has one downstream, no upstream.
    - It does not support downstream SYNs.
     
    When provided `None`, the node is in downstream mode:
    - It has one upstream, no downstream.
    """

def UDPNode(address: 
        tuple[IPv4Address | IPv6Address, int] | Literal["V4", "V6", "V4V6", "V6V4"] = "V4V6"
    ) -> Node:
    """
    Node for UDP, may bind a port. Doesn't support DNS.
    
    When provided `(ip, port)`, the node is in upstream mode:
    - The node listens to the port.
    - It has one downstream, no upstream.
    - It does not support downstream SYNs.
    
    When provided `V4V6 | V6V4 | V4 | V6`, the node is in downstream mode:
    - It binds ephemeral v4 | v6 | v4&v6 port(s). (`V4V6` and `V6V4` are treated the same here).
    - It has one upstream, no downstream.
    """

def DNSNode(
        resolver: str | IPv4Address | IPv6Address = IPv4Address("1.1.1.1"),  # noqa: B008
        middleware: bool = True,
        size: int = 5000,
        ttl: float = 300,
        *args,
        mode: Literal["V4", "V6", "V4V6", "V6V4"] = "V4",
        port: int = 53
    ) -> Node:
    """
    Node for DNS. Intercepts & blocks new connections with unresolved domain,
    releasing after resolution.
    
    When `middleware` is true, the node runs in middleware mode. The node
    will have one upstream and one downstream, acts purely as a middleware
    that resolves DNS locally.
    
    When `middleware` is false, the node runs in explicit mode. The node
    will have one upstream and two downstreams, in which the additional
    downstream is for DNS traffic.
    
    When operating with `V4` / `V6` address mode, DNSNode only tries to resolve
    into the given address family. `V4V6` / `V6V4` are treated the same here.
    
    User may specify the size and TTL of the node-local DNS cache.
    """

type PythonNodeCallbackArg = tuple[Literal["Signal"], Literal[-1], Signal] | tuple[Literal["Upstream", "Downstream"], int, Packet]

type PythonNodeCallback = Callable[[PythonNodeCallbackArg], bool | Signal]

def PythonNode(
        callback: PythonNodeCallback,
        upstreams: int,
        downstreams: int
    ) -> Node:
    """
    A python node. This node can be used to simply attach a python service to
    a graph, or listen to edge incoming packets.

    The callback is invoked when a signal or packet arrives.
    - If it returns a signal, the node quits and propagates the signal.
    - If it returns `True`, the node returns silently.
    - If it returns `False`, the node continues listening. (This is analogous to return 0.)

    Note that the node must be properly connected as usual, and `SIGTERM` 
    quits directly than invoking the callback.
    """
