# Script that harvests data flowing through the SOCKS proxy

import asyncio
from ipaddress import IPv4Address
from os import makedirs
from queue import Queue
from sys import stderr
from threading import Thread
from typing import BinaryIO

from penprox import *
from penprox.socks5 import SOCKS5Node

set_logger(stderr, LogLevel.DEBUG)

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

# Cache for file handler reuse throughout the connection lifetime
connections: dict[Connection, tuple[BinaryIO, BinaryIO]] = {}

# A minimal tokio in loop callback to first put stuff in python buffer
queue: Queue[PythonNodeCallbackArg] = Queue()
def callback(e: PythonNodeCallbackArg) -> bool | Signal:
    if e[0] == "Signal":
        return True
    queue.put_nowait(e)
    return False

python_node = PythonNode(callback, 1, 1)
ends: list[NodeEnd] = [python_node.upstreams[0], python_node.downstreams[0]]

graph = (
    TCPNode((IPv4Address("127.0.0.1"), 1080))
    >> SOCKS5Node()
    >> DNSNode()
    >> python_node
    >> TCPNode()
)

# Kick off the rust thread
Thread(target=graph.spawn).start()

# The main callback is async therefore needs an asyncio runtime.
# We'll use the main thread for this.
async def consume():
    while True:
        e = queue.get()
        if e[0] == "Upstream":
            end = ends[1]
            index = 0
        else:
            end = ends[0]
            index = 1

        packet: Packet = e[2] # pyright: ignore[reportAssignmentType]
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

        await end.put(packet)

asyncio.run(consume())
