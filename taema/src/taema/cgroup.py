"""Compatibility alias for :mod:`taema.core.cgroup`."""

import sys as _sys

from .core import cgroup as _implementation

_sys.modules[__name__] = _implementation
