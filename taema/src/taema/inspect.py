"""Compatibility alias for :mod:`taema.core.process`."""

import sys as _sys

from .core import process as _implementation

_sys.modules[__name__] = _implementation
