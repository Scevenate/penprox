"""
A drop-in import that registers a SIGINT handler for shutting graphs down.
"""

import signal
import sys

from ._src.sdk import running_graphs

penprox_sigints = 0

def sigint_handler(signum, frame):
    global penprox_sigints
    match penprox_sigints:
        case 0:
            print("[SIGINT=0] Gracefully shutting down graphs...", file=sys.stderr)
            for graph in running_graphs:
                graph.controller().sync_q.put_nowait("SIGTERM")
            running_graphs.iter_ok()
            penprox_sigints += 1
        case 1:
            print("[SIGINT=1] Aborting graphs...", file=sys.stderr)
            for graph in running_graphs:
                graph.controller().sync_q.put_nowait("SIGKILL")
            running_graphs.iter_ok()
            penprox_sigints += 1
        case 2:
            print("[SIGINT=2] exit(1)", file=sys.stderr)
            sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)

__all__ = []
