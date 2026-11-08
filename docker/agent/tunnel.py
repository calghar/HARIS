import contextlib
import os
import socket
import threading

LISTEN = 8080


def _pipe(source: socket.socket, sink: socket.socket) -> None:
    try:
        while chunk := source.recv(65536):
            sink.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (source, sink):
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)


def _handle(client: socket.socket, upstream: str) -> None:
    host, port = upstream.rsplit(":", 1)
    try:
        remote = socket.create_connection((host, int(port)), timeout=5)
    except OSError:
        client.close()
        return
    threading.Thread(target=_pipe, args=(client, remote), daemon=True).start()
    _pipe(remote, client)


def main() -> None:
    upstream = os.environ["UPSTREAM"]
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN))  # nosec B104 internal-net sidecar only
    server.listen(32)
    while True:
        client, _addr = server.accept()
        threading.Thread(target=_handle, args=(client, upstream), daemon=True).start()


if __name__ == "__main__":
    main()
