"""Small HTTP service used to demonstrate security automation."""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

MAX_NAME_LENGTH = 50
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,49}$")


def validate_name(value: str | None) -> str:
    if value is None or not value or len(value) > MAX_NAME_LENGTH or not NAME_PATTERN.fullmatch(value):
        raise ValueError("name must contain 1-50 safe characters")
    return value


class ApplicationHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: HTTPStatus, payload: dict[str, str]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        request = urlparse(self.path)
        if request.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if request.path == "/hello":
            try:
                name = validate_name(parse_qs(request.query).get("name", [None])[0])
            except ValueError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            self._send_json(HTTPStatus.OK, {"message": f"Hello, {name}!"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, format: str, *args: object) -> None:
        return


def create_server(host: str = "127.0.0.1", port: int = 8000) -> HTTPServer:
    return HTTPServer((host, port), ApplicationHandler)


if __name__ == "__main__":
    create_server().serve_forever()
