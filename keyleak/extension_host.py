"""Native-messaging host for the extension's local Docker scan runtime."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import sys
import time
from typing import Any
from urllib.request import Request, urlopen
from uuid import uuid4

from keyleak.extension_runtime import CHALLENGE_PATTERN, challenge_proof


HOST_NAME = "com.keyleak.detector"
COMPOSE_SERVICE = "keyleak-detector"
REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "compose.yml"
STATE_DIR = Path.home() / ".cache" / "keyleak-detector"
OWNER_FILE = STATE_DIR / "extension-host-owner.json"
LEASE_FILE = STATE_DIR / "extension-host-lease.json"
AUTH_FILE = STATE_DIR / "extension-host-auth.json"
SCANNER_HEALTH_URL = "http://127.0.0.1:5002/healthz"
IDLE_SECONDS = 300
STARTUP_SECONDS = 300


class NativeHostError(RuntimeError):
    """A safe, user-facing native-host failure."""


def is_keyleak_health(payload: object) -> bool:
    return bool(
        isinstance(payload, dict)
        and payload.get("status") == "ok"
        and payload.get("service") == COMPOSE_SERVICE
    )


def _state_dir() -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        STATE_DIR.chmod(0o700)
    except OSError:
        pass


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _state_dir()
    temporary = path.with_suffix(f".{uuid4().hex}.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def extension_token() -> str:
    payload = _read_json(AUTH_FILE) or {}
    token = str(payload.get("token") or "")
    if len(token) == 64:
        return token
    token = secrets.token_hex(32)
    _write_json(AUTH_FILE, {"token": token})
    return token


def scanner_health(
    challenge: str = "",
    expected_proof: str = "",
) -> dict[str, Any] | None:
    health_url = (
        f"{SCANNER_HEALTH_URL}?challenge={challenge}"
        if CHALLENGE_PATTERN.fullmatch(challenge)
        else SCANNER_HEALTH_URL
    )
    headers = {"Accept": "application/json"}
    if CHALLENGE_PATTERN.fullmatch(challenge) and expected_proof:
        headers["X-KeyLeak-Proof"] = expected_proof
    try:
        request = Request(health_url, headers=headers)
        with urlopen(request, timeout=2) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if is_keyleak_health(payload) else None


def docker_binary() -> str:
    candidates = (
        shutil.which("docker"),
        "/opt/homebrew/bin/docker",
        "/usr/local/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            # Docker and OrbStack use multicall binaries that dispatch from
            # argv[0], so preserve a `docker` symlink instead of resolving it.
            return str(Path(candidate).expanduser())
    raise NativeHostError("Docker Desktop is not installed or its Docker command is unavailable.")


def _run_docker(
    *args: str,
    timeout: int = 30,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [docker_binary(), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            check=check,
            env=env,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeHostError("Docker could not run the local KeyLeak scanner.") from error


def ensure_docker_ready() -> None:
    probe = _run_docker("info", timeout=10, check=False)
    if probe.returncode == 0:
        return

    if sys.platform == "darwin":
        try:
            subprocess.Popen(
                ["/usr/bin/open", "-gj", "-a", "Docker"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise NativeHostError("Docker Desktop could not be opened.") from error

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(2)
        if _run_docker("info", timeout=10, check=False).returncode == 0:
            return
    raise NativeHostError("Docker Desktop did not become ready. Open it and try RUN FULL SCAN again.")


def run_compose(*args: str, auth_token: str = "") -> None:
    if not COMPOSE_FILE.is_file():
        raise NativeHostError("The KeyLeak Compose file is missing from this checkout.")
    try:
        environment = os.environ.copy()
        if auth_token:
            environment["KEYLEAK_EXTENSION_TOKEN"] = auth_token
        _run_docker(
            "compose",
            "-f",
            str(COMPOSE_FILE),
            *args,
            env=environment,
            timeout=STARTUP_SECONDS,
        )
    except NativeHostError as error:
        raise NativeHostError(
            "Docker Compose could not manage the local KeyLeak scanner. Check Docker Desktop and try again."
        ) from error


def compose_container_id() -> str | None:
    result = _run_docker(
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "ps",
        "-q",
        COMPOSE_SERVICE,
        timeout=20,
        check=False,
    )
    container_id = result.stdout.strip().splitlines()
    return container_id[0] if result.returncode == 0 and container_id else None


def read_owner() -> dict[str, Any] | None:
    return _read_json(OWNER_FILE)


def write_owner(container_id: str) -> None:
    _write_json(OWNER_FILE, {"container_id": container_id})


def clear_owner() -> None:
    OWNER_FILE.unlink(missing_ok=True)
    LEASE_FILE.unlink(missing_ok=True)


def renew_lease() -> str:
    lease = _read_json(LEASE_FILE) or {}
    token = str(lease.get("token") or uuid4().hex)
    _write_json(LEASE_FILE, {"token": token, "touched_at": time.time()})
    return token


def schedule_watchdog(token: str) -> None:
    subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--watchdog", token],
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def ensure_running(challenge: str) -> dict[str, Any]:
    if not CHALLENGE_PATTERN.fullmatch(challenge):
        raise NativeHostError("The extension startup challenge is invalid.")
    auth_token = extension_token()
    expected_proof = challenge_proof(auth_token, challenge)
    ensure_docker_ready()
    existing_container = compose_container_id()
    owner = read_owner()
    existing_was_owned = bool(
        existing_container
        and owner
        and owner.get("container_id") == existing_container
    )
    if scanner_health(challenge, expected_proof):
        if not existing_container:
            raise NativeHostError(
                "The authenticated local service is not the managed Compose container."
            )
        owned = existing_was_owned
        if owned:
            renew_lease()
        return {
            "ok": True,
            "status": "already_running",
            "owned": owned,
            "proof": expected_proof,
        }

    existing_health = scanner_health()
    if existing_health and not existing_was_owned:
        raise NativeHostError(
            "A manually managed KeyLeak scanner is already using the local port "
            "without extension authentication. Stop it, then try RUN FULL SCAN again."
        )
    run_compose("up", "-d", COMPOSE_SERVICE, auth_token=auth_token)

    deadline = time.monotonic() + STARTUP_SECONDS
    while time.monotonic() < deadline:
        health = scanner_health(challenge, expected_proof)
        if health:
            break
        time.sleep(1)
    else:
        raise NativeHostError("The KeyLeak scanner did not become healthy after Docker started it.")

    container_id = compose_container_id()
    owned = bool(container_id and existing_was_owned)
    if container_id and (not existing_container or existing_was_owned):
        write_owner(container_id)
        owned = True

    if owned:
        token = renew_lease()
        schedule_watchdog(token)
    return {
        "ok": True,
        "status": "started",
        "owned": owned,
        "proof": expected_proof,
    }


def touch() -> dict[str, Any]:
    if not read_owner():
        return {"ok": True, "owned": False}
    renew_lease()
    return {"ok": True, "owned": True}


def stop_owned_container() -> bool:
    owner = read_owner()
    if not owner or owner.get("container_id") != compose_container_id():
        return False
    run_compose("stop", COMPOSE_SERVICE)
    clear_owner()
    return True


def run_watchdog(token: str) -> None:
    while True:
        lease = _read_json(LEASE_FILE)
        if not lease or lease.get("token") != token:
            return
        try:
            remaining = IDLE_SECONDS - (time.time() - float(lease["touched_at"]))
        except (KeyError, TypeError, ValueError):
            return
        if remaining > 0:
            time.sleep(min(remaining, 30))
            continue

        health = scanner_health() or {}
        if health.get("scan_active"):
            time.sleep(30)
            continue
        stop_owned_container()
        return


def handle_message(message: object) -> dict[str, Any]:
    if not isinstance(message, dict):
        return {"ok": False, "code": "INVALID_MESSAGE", "error": "Invalid native-host message."}
    action = message.get("action")
    try:
        if action == "ensure_running":
            if set(message) != {"action", "challenge"}:
                return {"ok": False, "code": "INVALID_MESSAGE", "error": "Invalid native-host message."}
            challenge = message.get("challenge")
            if not isinstance(challenge, str) or not CHALLENGE_PATTERN.fullmatch(challenge):
                return {"ok": False, "code": "INVALID_MESSAGE", "error": "Invalid native-host message."}
            return ensure_running(challenge)
        if action == "touch":
            if set(message) != {"action"}:
                return {"ok": False, "code": "INVALID_MESSAGE", "error": "Invalid native-host message."}
            return touch()
        return {"ok": False, "code": "UNSUPPORTED_ACTION", "error": "Unsupported native-host action."}
    except NativeHostError as error:
        return {"ok": False, "code": "START_FAILED", "error": str(error)}
    except Exception:
        return {"ok": False, "code": "HOST_FAILED", "error": "The KeyLeak startup helper failed."}


def _read_message() -> object:
    length_bytes = sys.stdin.buffer.read(4)
    if len(length_bytes) != 4:
        raise EOFError
    length = struct.unpack("<I", length_bytes)[0]
    if length > 1024 * 1024:
        raise ValueError("message too large")
    payload = sys.stdin.buffer.read(length)
    if len(payload) != length:
        raise EOFError
    return json.loads(payload.decode("utf-8"))


def _write_message(message: dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--watchdog":
        run_watchdog(sys.argv[2])
        return 0
    try:
        message = _read_message()
    except (EOFError, ValueError, json.JSONDecodeError):
        return 1
    _write_message(handle_message(message))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
