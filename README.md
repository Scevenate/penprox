# Penprox
[![PyPI Version](https://img.shields.io/pypi/v/penprox)](https://pypi.org/project/penprox/)
[![Crates.io Version](https://img.shields.io/crates/v/penprox)](https://crates.io/crates/penprox)

> [!NOTE]
> This project is still in beta phase. I haven't wrote a comprehensive documentation for it yet but the core interface is quite stable.

Penprox is a library for prototyping network applications. You draw a graph in python, and it compiles to a multithreaded tokio native pipeline so it's expected to be quite fast.

## Example

Alice wants a SOCKS5 server. So she has one:

```python
from penprox import *

graph = \
    # This is where packets come in
    TCPNode((IPv4Address("10.68.0.16"), 1080)) >> \
    # This is the server. If you supply an server address argument
    # it becomes a client, similar to how the two TCPNode works here.
    SOCKS5Node() >> \
    # 1.1.1.1 Resolve middleware. this is a very flexible node and please
    # refer to docs to see what crazy stuff it can do...
    DNSNode() >> \
    # This is the packet exit
    TCPNode()

# Hand over current thread to run tokio
# (Detaches GIL + block until graph return,
# For our graph it's run forever)
graph.spawn()
```

Alice thinks it's not safe. So Alice adds a TLS layer to her server:

```python
from penprox import *

graph = \
    TCPNode((IPv4Address("10.68.0.16"), 1080)) >> \
    # If you don't give the paths it's a TLS client
    TLSNode(("./cert.pem", "./key.pem")) >> \
    SOCKS5Node() >> \
    DNSNode() >> \
    TCPNode()

graph.spawn()
```

Alice still feels a little insecure. What if the attacker breaks TLS? Alice decided to operate a TLS-in-TLS server to improve security (*for plot purpose*):

```python
from penprox import *

graph = \
    TCPNode((IPv4Address("10.68.0.16"), 1080)) >> \
    TLSNode(("./cert.pem", "./key.pem")) >> \
    TLSNode(("./cert.pem", "./key.pem")) >> \
    SOCKS5Node() >> \
    DNSNode() >> \
    TCPNode()

graph.spawn()
```

That feels much better. Now Bob also wants to use Alice's SOCKS5 server. But Alice is *very interested* in what Bob is browsing. But penprox doesn't provide a node for harvesting data. So Alice can build one herself:

```python
from ipaddress import IPv4Address

from penprox import *

ends: list[NodeUpstreamEnd | NodeDownstreamEnd] = []

id = 0

# This handler is simplified for readability, see more examples for full handling
async def harvest(incoming: PythonNodeCallbackArg) -> PythonNodeCallbackReturn:
    packet: Packet = incoming[0]
    if packet.payload == "SYN" or packet.payload == "FIN":
        return False # Return 0, continue listening

    with open(f"{id}_{packet.type}_{packet.connection.host}", "wb") as f:
        f.write(packet.payload)

    # Let packet flow through, as if nothing happened...
    match packet.type:
        case "Downward":
            await ends[1].put(packet)
        case "Upward":
            await ends[0].put(packet)

    return False

# It runs a asyncio runtime for you (Process global worker)
# You don't pay for that if you just do sync function
python_node = PythonNode(harvest, 1, 1)

# Populate the ends handle
ends.append(python_node.upstreams[0])
ends.append(python_node.downstreams[0])

graph = \
    TCPNode((IPv4Address("10.68.0.16"), 1080)) >> \
    TLSNode(("./cert.pem", "./key.pem")) >> \
    TLSNode(("./cert.pem", "./key.pem")) >> \
    SOCKS5Node() >> \
    DNSNode() >> \
    TCPNode()

graph.spawn()
```
