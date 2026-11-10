from collections.abc import Callable
from typing import Literal

from ._src.penprox.common import *
from .sdk import *

type PythonNodeCallbackArg = tuple[Literal["Signal"], Literal[-1], Signal] | tuple[Literal["Upstream", "Downstream"], int, Packet] # pyright: ignore[reportUndefinedVariable]

type PythonNodeCallback = Callable[[PythonNodeCallbackArg], bool | Signal]
