"""Compatibility alias for :mod:`taema.model.authorization`."""

import sys as _sys

from .model import authorization as _implementation

_sys.modules[__name__] = _implementation
