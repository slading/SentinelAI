"""Authentication dependencies for privileged API operations.

The public deployment is read-only. A single API key is supported only for
controlled, non-production local/private testing; it is deliberately disabled
for Vercel and any runtime marked as production.
"""

from __future__ import annotations

import hmac
import os
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _disabled_error() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def _unavailable_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Privileged operations are unavailable.",
    )


def _unauthorized_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def is_production_runtime() -> bool:
    """Treat production and all Vercel deployments as non-privileged runtimes."""
    environment = os.getenv("ENVIRONMENT", "").strip().lower()
    vercel_env = os.getenv("VERCEL_ENV", "").strip().lower()
    vercel = os.getenv("VERCEL", "").strip().lower()
    return (
        environment in {"prod", "production"}
        or bool(vercel_env)
        or vercel in {"1", "true", "yes", "on"}
    )


def is_controlled_nonproduction_runtime() -> bool:
    """Require an explicit local/test designation before enabling private mode."""
    environment = os.getenv("ENVIRONMENT", "").strip().lower()
    return environment in {"development", "dev", "local", "private", "test", "testing"}


def _configured_api_key() -> Optional[bytes]:
    """Return a usable configured key, or None; never provide a dev fallback."""
    value = os.getenv("SENTINELAI_PRIVILEGED_API_KEY", "")
    if not value or not value.isascii() or len(value.encode("ascii")) < 32:
        return None
    return value.encode("ascii")


async def require_privileged_api_key(
    presented_key: Optional[str] = Security(_api_key_header),
) -> None:
    """Deny by default; permit a valid key only in explicit non-production mode."""
    # Public production and serverless deployments are always read-only, even if
    # an operator accidentally sets the private-mode variables there.
    if is_production_runtime():
        raise _disabled_error()

    mode = os.getenv("SENTINELAI_PRIVILEGED_MODE", "disabled").strip().lower()
    if mode == "disabled":
        raise _disabled_error()
    if mode != "api_key":
        raise _unavailable_error()
    if not is_controlled_nonproduction_runtime():
        raise _disabled_error()

    expected_key = _configured_api_key()
    if expected_key is None:
        # Keep the public/read-only app alive, but never allow an incomplete
        # private configuration to fall through to an unauthenticated path.
        raise _unavailable_error()

    supplied_key = presented_key or ""
    try:
        supplied_bytes = supplied_key.encode("ascii")
    except UnicodeEncodeError:
        supplied_bytes = b""

    matches = hmac.compare_digest(supplied_bytes, expected_key)
    if not supplied_bytes or not matches:
        # Missing and incorrect client credentials deliberately share the same
        # response, and the presented value is never logged.
        raise _unauthorized_error()
