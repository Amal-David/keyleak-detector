"""Route browser HTTP through guarded requests and deny native HTTP tunnels."""

import base64
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
import logging
import socketserver
import threading
import time
from urllib.parse import urlsplit

from .net_guard import SSRFBlocked
from .proxy import requests_proxies


MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_PENDING_REDIRECTS = 1000
_LOG = logging.getLogger(__name__)


class _DenyNativeRequest(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.close()


@contextmanager
def denied_browser_proxy():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _DenyNativeRequest) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
        thread.start()
        try:
            yield {"server": f"http://127.0.0.1:{server.server_address[1]}", "bypass": "<-loopback>"}
        finally:
            server.shutdown()
            thread.join(timeout=2)


def install_guarded_routes(page, target_url, check_url, fetch, proxy=None, *, request_timeout=30):
    context = page.context

    def origin(url):
        parsed = urlsplit(url)
        return parsed.scheme.lower(), parsed.hostname, parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)

    credentials_origin = origin(target_url)
    state = {"blocked": 0, "failed": 0}
    sensitive = {"authorization", "cookie", "proxy-authorization", "apikey", "x-api-key"}

    session = context.new_cdp_session(page)
    redirects = {}

    def intercept(event):
        request_id = event["requestId"]
        try:
            previous = event.get("redirectedRequestId")
            if previous:
                deadline, credentials_allowed, hops = redirects.pop(previous)
            else:
                deadline, credentials_allowed, hops = time.monotonic() + request_timeout, True, 0
            if time.monotonic() >= deadline or hops > 20:
                raise TimeoutError("Browser request exceeded its deadline or redirect limit")
            request = event["request"]
            current = request["url"]
            reason = check_url(current)
            if reason:
                raise SSRFBlocked(reason)
            credentials_allowed = credentials_allowed and origin(current) == credentials_origin
            headers = {key: value for key, value in request["headers"].items()
                       if key.lower() not in {"host", "accept-encoding"}}
            headers["Accept-Encoding"] = "gzip, deflate"
            if not credentials_allowed:
                headers = {key: value for key, value in headers.items() if key.lower() not in sensitive}
            body = None
            if request.get("postDataEntries"):
                body = b"".join(base64.b64decode(entry["bytes"], validate=True) for entry in request["postDataEntries"])
            elif "postData" in request:
                body = request["postData"].encode("utf-8")
            elif request.get("hasPostData"):
                raise ValueError("Browser request body is unavailable")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Browser request exceeded the transport deadline")
            response = fetch(request["method"], current, headers=headers, data=body,
                             proxies=requests_proxies(proxy), timeout=min(15, remaining), stream=True)

            def expire_response():
                try:
                    response.raw.shutdown()
                except Exception as exc:
                    _LOG.debug("Browser response shutdown failed (%s)", type(exc).__name__)

            timer = threading.Timer(max(0, deadline - time.monotonic()), expire_response)
            timer.daemon = True
            timer.start()
            try:
                # Read each field separately; Expires can itself contain a comma.
                if credentials_allowed:
                    parsed_url = urlsplit(current)
                    for field in response.raw.headers.getlist("Set-Cookie"):
                        parsed_cookies = SimpleCookie()
                        try:
                            parsed_cookies.load(field)
                        except CookieError:
                            continue
                        for cookie in parsed_cookies.values():
                            if cookie["domain"] and cookie["domain"].lstrip(".").lower() != parsed_url.hostname:
                                continue
                            path = cookie["path"]
                            if not path.startswith("/"):
                                path = parsed_url.path.rsplit("/", 1)[0] or "/"
                            entry = {"name": cookie.key, "value": cookie.value,
                                     "domain": parsed_url.hostname, "path": path,
                                     "secure": bool(cookie["secure"]), "httpOnly": bool(cookie["httponly"])}
                            if cookie["samesite"].capitalize() in {"Lax", "Strict", "None"}:
                                entry["sameSite"] = cookie["samesite"].capitalize()
                            try:
                                if cookie["max-age"]:
                                    entry["expires"] = max(1, time.time() + int(cookie["max-age"]))
                                elif cookie["expires"]:
                                    entry["expires"] = max(1, parsedate_to_datetime(cookie["expires"]).timestamp())
                            except (ValueError, TypeError, OverflowError):
                                pass
                            context.add_cookies([entry])
                location = response.headers.get("location") or response.headers.get("Location")
                response_headers = [{"name": key, "value": value} for key, value in response.headers.items()
                                    if key.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}]
                chunks, size = [], 0
                if response.status_code in (301, 302, 303, 307, 308) and location:
                    if len(redirects) >= MAX_PENDING_REDIRECTS:
                        raise ValueError("Browser pending redirect limit exceeded")
                    redirects[request_id] = (deadline, credentials_allowed, hops + 1)
                else:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Browser response exceeded the transport deadline")
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise ValueError("Browser response exceeded the transport size limit")
                        chunks.append(chunk)
                if time.monotonic() >= deadline:
                    raise TimeoutError("Browser response exceeded the transport deadline")
                session.send("Fetch.fulfillRequest", {"requestId": request_id,
                             "responseCode": response.status_code, "responseHeaders": response_headers,
                             "body": base64.b64encode(b"".join(chunks)).decode("ascii")})
            finally:
                timer.cancel()
                response.close()
            return
        except SSRFBlocked:
            state["blocked"] += 1
        except Exception as exc:
            # Exception text can contain credential-bearing URLs or headers.
            _LOG.debug("Guarded browser request failed closed (%s)", type(exc).__name__)
            state["failed"] += 1
        redirects.pop(request_id, None)
        try:
            session.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
        except Exception as exc:
            _LOG.debug("Guarded browser route abort failed (%s)", type(exc).__name__)

    session.on("Fetch.requestPaused", intercept)
    # CDP pauses every redirect hop; Playwright's route API only routes the first.
    session.send("Fetch.enable", {"patterns": [{"urlPattern": "http://*", "requestStage": "Request"},
                                               {"urlPattern": "https://*", "requestStage": "Request"}]})

    def block_socket(_route):
        # Routed sockets never reach the server without connect_to_server().
        # Synchronous close during the pending handshake can stall Playwright.
        state["blocked"] += 1

    context.route_web_socket("**/*", block_socket)
    return state
