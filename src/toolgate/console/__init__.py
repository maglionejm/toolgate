"""Operator console: a static single-page app served at /console."""

from importlib.resources import files
from pathlib import Path


def static_dir() -> Path:
    return Path(str(files("toolgate.console") / "static"))
