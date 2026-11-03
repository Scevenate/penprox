# Register submodules

import sys as _sys

from ._src import penprox as _penprox

for _name in ("common", "sdk", "socks5"):
    _sys.modules[f"{__name__}._src.penprox.{_name}"] = getattr(_penprox, _name)

del _name, _penprox, _sys

# Import basic objects

from .common import *
from .sdk import *
