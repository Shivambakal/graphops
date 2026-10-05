"""Vercel ASGI entrypoint for the GraphOps API."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphops.api.server import app

__all__ = ["app"]
