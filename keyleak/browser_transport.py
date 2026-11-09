"""Route browser HTTP through guarded requests and deny native HTTP tunnels."""

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
import logging
import socketserver
import threading
import time
from urllib.parse import urljoin, urlsplit

from .net_guard import SSRFBlocked
from .proxy import requests_proxies


MAX_RESPONSE_BYTES = 10 * 1024 * 1024
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


def install_guarded_routes(context, target_url, check_url, fetch, proxy=None):
    def origin(url):
        parsed = urlsplit(url)
        return parsed.scheme.lower(), parsed.hostname, parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)

    credentials_origin = origin(target_url)
    state = {"blocked": 0, "failed": 0}
    sensitive = {"authorization", "cookie", "proxy-authorization", "apikey", "x-api-key"}

    def intercept(route):
        request = route.request
        current, method, body = request.url, request.method, request.post_data_buffer
        headers = {key: value for key, value in request.all_headers().items()
                   if key.lower() not in {"host", "accept-encoding"}}
        headers["Accept-Encoding"] = "gzip, deflate"
        credentials_allowed = True
        try:
            for _hop in range(21):
                reason = check_url(current)
                if reason:
                    raise SSRFBlocked(reason)
                if origin(current) != credentials_origin:
                    credentials_allowed = False
                if not credentials_allowed:
                    headers = {key: value for key, value in headers.items() if key.lower() not in sensitive}
                elif _hop:
                    headers = {key: value for key, value in headers.items() if key.lower() != "cookie"}
                    cookies = context.cookies(current)
                    if cookies:
                        headers["Cookie"] = "; ".join(f'{cookie["name"]}={cookie["value"]}' for cookie in cookies)
                response = fetch(method, current, headers=headers, data=body,
                                 proxies=requests_proxies(proxy), timeout=15, stream=True)
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
                    if response.status_code in (301, 302, 303, 307, 308) and location:
                        current = urljoin(current, location)
                        if response.status_code == 303 and method != "HEAD" or response.status_code in (301, 302) and method == "POST":
                            method, body = "GET", None
                            headers = {key: value for key, value in headers.items() if key.lower() not in {"content-length", "content-type"}}
                        continue
                    response_headers = {key: value for key, value in response.headers.items()
                                        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}}
                    chunks, size = [], 0
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise ValueError("Browser response exceeded the transport size limit")
                        chunks.append(chunk)
                    route.fulfill(status=response.status_code, headers=response_headers, body=b"".join(chunks))
                    return
                finally:
                    response.close()
            raise ValueError("Browser request exceeded the redirect limit")
        except SSRFBlocked:
            state["blocked"] += 1
        except Exception as exc:
            # Exception text can contain credential-bearing URLs or headers.
            _LOG.debug("Guarded browser request failed closed (%s)", type(exc).__name__)
            state["failed"] += 1
        route.abort()

    def block_socket(_route):
        # Routed sockets never reach the server without connect_to_server().
        # Synchronous close during the pending handshake can stall Playwright.
        state["blocked"] += 1

    context.route("**/*", intercept)
    context.route_web_socket("**/*", block_socket)
    return state
