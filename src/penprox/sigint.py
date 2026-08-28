"""
A drop-in import that broadcasts signals to all running graphs when
received system SIGINT.
"""

from ._src.framework import _penprox_running_graphs
import sys
import signal

_penprox_sigints = 0

def sigint_handler(signum, frame):
    global _penprox_sigints
    match _penprox_sigints:
        case 0:
            print("[SIGINT=0] Gracefully shutting down graphs...", file=sys.stderr)
            for graph in _penprox_running_graphs:
                graph.controller().sync_put("SIGTERM")
            _penprox_running_graphs.iter_ok()
            _penprox_sigints += 1
        case 1:
            print("[SIGINT=1] Aborting graphs...", file=sys.stderr)
            for graph in _penprox_running_graphs:
                graph.controller().sync_put("SIGKILL")
            _penprox_running_graphs.iter_ok()
            _penprox_sigints += 1
        case 2:
            print("[SIGINT=2] exit(1)", file=sys.stderr)
            exit(1)

signal.signal(signal.SIGINT, sigint_handler)

__all__ = []
