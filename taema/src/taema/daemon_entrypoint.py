"""Lightweight startup path for the supervised per-user daemon."""

import sys


def launch_daemon(config_path=None, socket_override=None):
    """Load daemon configuration and start the service for CLI and runit callers."""
    from .config import policy
    from .daemon import service

    cfg = policy.load_config(path=config_path)
    if socket_override:
        socket_override = policy.expand(socket_override)
        cfg["paths"]["socket"] = socket_override
        cfg["paths"]["socket_fallback"] = socket_override
    return service.run(cfg)


def main():
    """Start the supervised daemon without importing the general CLI dispatcher."""
    return launch_daemon()


if __name__ == "__main__":
    sys.exit(main())
