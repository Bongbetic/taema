"""Daemon service package with the legacy ``taema.daemon`` exports."""

from . import service as _implementation

globals().update(
    {
        name: value
        for name, value in vars(_implementation).items()
        if not name.startswith("_")
    }
)
del _implementation
