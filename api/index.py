"""Vercel serverless entry — re-exports the GraphOps FastAPI app.

Vercel forwards /api/* here (see vercel.json). The _StripApiPrefix middleware
makes routing work whether Vercel passes the original path (/api/hunt) or the
rewritten one (/hunt).
"""
import sys
from pathlib import Path

_BUILD_DIR = Path(__file__).resolve().parents[1]
if str(_BUILD_DIR) not in sys.path:
    sys.path.insert(0, str(_BUILD_DIR))

from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402

from graphops.api.server import app as fastapi_app  # noqa: E402


class _StripApiPrefix(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        p = request.scope.get("path", "")
        # Vercel preserves the original request path through the rewrite,
        # so /api/hunt arrives as /api/hunt -> strip to /hunt.
        # If Vercel ever passes the rewritten /api/index instead, fall back to /.
        if p in ("/api", "/api/", "/api/index"):
            request.scope["path"] = "/"
        elif p.startswith("/api/"):
            request.scope["path"] = p[4:]
        return await call_next(request)


fastapi_app.add_middleware(_StripApiPrefix)

app = fastapi_app
