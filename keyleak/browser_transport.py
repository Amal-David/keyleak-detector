"""Route browser HTTP through guarded requests and deny native HTTP tunnels."""

from contextlib import contextmanager
import socketserver
import threading
from urllib.parse import urljoin, urlsplit

from .proxy import requests_proxies


MAX_RESPONSE_BYTES = 10 * 1024 * 1024


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
    state = {"blocked": 0}
    sensitive = {"authorization", "cookie", "proxy-authorization", "apikey", "x-api-key"}

    def intercept(route):
        request = route.request
        current, method, body = request.url, request.method, request.post_data_buffer
        headers = dict(request.all_headers())
        try:
            for _hop in range(21):
                if check_url(current):
                    break
                if origin(current) != credentials_origin:
                    headers = {key: value for key, value in headers.items() if key.lower() not in sensitive}
                response = fetch(method, current, headers=headers, data=body,
                                 proxies=requests_proxies(proxy), timeout=15, stream=True)
                try:
                    location = response.headers.get("location") or response.headers.get("Location")
                    if response.status_code in (301, 302, 303, 307, 308) and location:
                        current = urljoin(current, location)
                        if response.status_code == 303 and method != "HEAD" or response.status_code in (301, 302) and method == "POST":
                            method, body = "GET", None
                            headers = {key: value for key, value in headers.items() if key.lower() not in {"content-length", "content-type"}}
                        continue
                    response_headers = {key: value for key, value in response.headers.items()
                                        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection"}}
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
        except Exception:
            pass
        state["blocked"] += 1
        route.abort()

    def block_socket(_route):
        # Routed sockets never reach the server without connect_to_server().
        # Synchronous close during the pending handshake can stall Playwright.
        state["blocked"] += 1

    context.route("**/*", intercept)
    context.route_web_socket("**/*", block_socket)
    return state
