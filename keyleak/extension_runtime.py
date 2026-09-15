"""Shared authentication and activity tracking for extension-triggered scans."""

from __future__ import annotations

from functools import wraps
import hashlib
import hmac
import re
import threading
from typing import Any, Awaitable, Callable, TypeVar


CHALLENGE_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_ReturnValue = TypeVar("_ReturnValue")


def challenge_proof(token: str, challenge: str) -> str:
    """Return an HMAC proof only for a valid extension challenge."""

    if not token or not CHALLENGE_PATTERN.fullmatch(challenge):
        return ""
    return hmac.new(
        token.encode("utf-8"),
        challenge.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def proof_matches(token: str, challenge: str, proof: str) -> bool:
    """Compare a supplied extension proof without timing-sensitive equality."""

    expected = challenge_proof(token, challenge)
    return bool(expected and hmac.compare_digest(expected, str(proof)))


class ActiveScanCounter:
    """Track overlapping async scans and reset state even when handlers fail."""

    def __init__(self) -> None:
        self._count = 0
        self._lock = threading.Lock()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._count > 0

    def track(
        self,
        handler: Callable[..., Awaitable[_ReturnValue]],
    ) -> Callable[..., Awaitable[_ReturnValue]]:
        @wraps(handler)
        async def tracked(*args: Any, **kwargs: Any) -> _ReturnValue:
            with self._lock:
                self._count += 1
            try:
                return await handler(*args, **kwargs)
            finally:
                with self._lock:
                    self._count -= 1

        return tracked
