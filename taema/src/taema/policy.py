"""Compatibility alias for :mod:`taema.config.policy`."""

import sys as _sys

from .config import policy as _implementation

_sys.modules[__name__] = _implementation
