import sys
from ipaddress import IPv4Address
from os import makedirs
from typing import BinaryIO

from penprox import *

set_logger(sys.stderr, LogLevel.DEBUG)

# Harvest all proxied data to data/
makedirs("data", exist_ok=True)
file_id = 0
def ConnectionFiles(connection: Connection) -> tuple[BinaryIO, BinaryIO]:
    global file_id
    file_id += 1
    return (
        open(f"data/{file_id}_{connection.host}_{connection.port}_forward", "ab"),
        open(f"data/{file_id}_{connection.host}_{connection.port}_backward", "ab"),
    )
connections: dict[Connection, tuple[BinaryIO, BinaryIO]] = {}

ends: list[NodeUpstreamEnd | NodeDownstreamEnd] = []

async def harvest(incoming: PythonNodeCallbackArg) -> PythonNodeCallbackReturn:
    if isinstance(incoming[0], str):
        return True

    packet = incoming[0]
    index = int(packet.type == "Downward")

    if isinstance(packet.payload, bytes):
        files = connections.get(packet.connection)
        if files is None:
            files = ConnectionFiles(packet.connection)
            connections[packet.connection] = files
        files[index].write(packet.payload)
        files[index].flush()

    if packet.payload == "FIN":
        files = connections.pop(packet.connection, None)
        if files is not None:
            for file in files:
                file.close()

    await ends[1].put(packet)
    return False

python_node = PythonNode(harvest, 1, 1)

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