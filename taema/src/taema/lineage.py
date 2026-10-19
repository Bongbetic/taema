"""Compatibility alias for :mod:`taema.core.lineage`."""

import sys as _sys

from .core import lineage as _implementation

_sys.modules[__name__] = _implementation
