"""Command-line package with the legacy ``taema.cli`` exports."""

from . import commands as _implementation

globals().update(
    {
        name: value
        for name, value in vars(_implementation).items()
        if not name.startswith("_")
    }
)
del _implementation
