from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path


def log_directory() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    return root / "WsVpn" / "logs"


def configure_file_logging(*, verbose: bool = False) -> Path:
    directory = log_directory()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "ws-vpn.log"
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)
    # websockets can log HTTP headers at DEBUG; keep credentials out of logs.
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("ws-vpn.wire").setLevel(logging.WARNING)
    return path
