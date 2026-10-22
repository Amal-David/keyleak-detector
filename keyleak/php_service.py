"""Public PHP banner assessment service, independent of the local scanner bridge."""

from collections import OrderedDict, deque
import hashlib
import hmac
import secrets
from pathlib import Path
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

from .php_scanner import scan_php_url, validate_php_url


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
_slots = threading.BoundedSemaphore(4)
_lock = threading.Lock()
_requests = deque()
_targets = OrderedDict()
_limiter_key = secrets.token_bytes(32)
_origins = {"https://keyleakdetector.com", "https://www.keyleakdetector.com"}
_site = Path(__file__).resolve().parent.parent / "site" / "php-check"


@app.after_request
def response_headers(response):
    origin = request.headers.get("Origin")
    if origin in _origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


@app.get("/healthz")
def health():
    return jsonify(status="ok", service="keyleak-php-check")


@app.get("/")
def index():
    return send_from_directory(_site, "index.html")


@app.get("/checker.js")
def javascript():
    return send_from_directory(_site, "checker.js")


@app.route("/api/check", methods=["POST", "OPTIONS"])
def check():
    origin = request.headers.get("Origin")
    same_origin = request.host_url.rstrip("/")
    if origin and origin not in _origins and origin not in {same_origin, "https://" + request.host}:
        return jsonify(error="This origin is not permitted."), 403
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get("authorized") is not True or not isinstance(payload.get("url"), str):
        return jsonify(error="Provide a URL and confirm ownership or permission."), 400
    url = payload["url"].strip()
    try:
        target = validate_php_url(url).hostname
    except ValueError:
        return jsonify(error="Provide a public HTTP(S) URL without credentials or query strings."), 400
    target = hmac.digest(_limiter_key, target.encode(), hashlib.sha256)
    now = time.monotonic()
    with _lock:
        while _requests and _requests[0] <= now - 60:
            _requests.popleft()
        while _targets and next(iter(_targets.values())) <= now - 60:
            _targets.popitem(last=False)
        last = _targets.get(target)
        if len(_requests) >= 120 or (last is not None and last > now - 30):
            response = jsonify(error="Assessment limit reached. Try again in one minute.")
            response.headers["Retry-After"] = "60"
            return response, 429
        _requests.append(now)
        _targets[target] = now
        _targets.move_to_end(target)
        while len(_targets) > 512:
            _targets.popitem(last=False)
    if not _slots.acquire(blocking=False):
        return jsonify(error="The checker is busy. Try again shortly."), 429
    try:
        report = scan_php_url(url)
        return jsonify(report.extra["php_assessment"])
    except ValueError:
        return jsonify(error="Use a public HTTP(S) URL on port 80 or 443, without credentials or query strings."), 400
    finally:
        _slots.release()
