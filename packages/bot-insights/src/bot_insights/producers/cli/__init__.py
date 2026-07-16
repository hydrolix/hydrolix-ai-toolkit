"""Bot Insights producer CLI package."""

from __future__ import annotations

from .args import parse_args
from .dispatcher import main

__all__ = ["main", "parse_args"]
