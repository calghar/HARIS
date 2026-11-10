import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager

ENDPOINT_EVENT = b"event: endpoint\ndata: /messages\n\n"
HOLD_OPEN_S = 10.0


@contextmanager
def hanging_sse_server(first_event: bytes = ENDPOINT_EVENT) -> Iterator[str]:
    """Loopback server whose ``/sse`` sends one event, then keeps the stream open."""
    release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/sse":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(first_event)
            self.wfile.flush()
            release.wait(HOLD_OPEN_S)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        release.set()
        server.shutdown()
        server.server_close()
