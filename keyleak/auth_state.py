"""Limit browser credentials to the operator's exact target origin."""

import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit


def scoped_auth_state(path: str, target_url: str) -> dict:
    target = urlsplit(target_url)
    target_origin = (target.scheme.lower(), target.hostname, target.port if target.port is not None else (443 if target.scheme == "https" else 80))
    try:
        descriptor = os.open(Path(path).expanduser(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not a regular file")
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("auth state exceeds limit")
        state = json.loads(raw)
        if not isinstance(state, dict) or any(not isinstance(state.get(key, []), list) for key in ("cookies", "origins")):
            raise ValueError("invalid auth state")
    except (OSError, ValueError, RecursionError):
        raise ValueError("Browser auth state could not be read or was invalid") from None

    cookies = [cookie for cookie in state.get("cookies", [])
               if isinstance(cookie, dict) and isinstance(cookie.get("domain"), str)
               and cookie["domain"].lower() == target.hostname]
    origins = []
    for item in state.get("origins", []):
        if not isinstance(item, dict) or not isinstance(item.get("origin"), str):
            continue
        try:
            origin = urlsplit(item["origin"])
            identity = (origin.scheme.lower(), origin.hostname, origin.port if origin.port is not None else (443 if origin.scheme == "https" else 80))
            if identity == target_origin and not origin.username and not origin.password:
                origins.append(item)
        except ValueError:
            continue
    return {"cookies": cookies, "origins": origins}
