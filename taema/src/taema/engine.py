"""Compatibility alias for :mod:`taema.governor.engine`."""

import sys as _sys

from .governor import engine as _implementation

_sys.modules[__name__] = _implementation
