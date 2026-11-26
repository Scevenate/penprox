from .crate.penprox import *  # noqa: I001




from collections.abc import Awaitable, Callable
from typing import Literal

from .crate.penprox import Packet


type Signal = Literal["SIGTERM", "SIGUSR1", "SIGUSR2"]

type PacketType = Literal["Detached", "Upward", "Downward"]

type PacketPayload = Literal["SYN", "FIN"] | bytes

type PythonNodeCallbackArg = tuple[Signal, Literal[0]] | tuple[Packet, int]

type PythonNodeCallbackReturn = bool | Signal

type PythonNodeCallback = Callable[[PythonNodeCallbackArg], PythonNodeCallbackReturn | Awaitable[PythonNodeCallbackReturn]]

