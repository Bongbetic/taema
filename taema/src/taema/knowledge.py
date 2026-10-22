"""Compatibility alias for :mod:`taema.store.knowledge`."""

import sys as _sys

from .store import knowledge as _implementation

_sys.modules[__name__] = _implementation
