"""Public-only source HTTP connections; private qBittorrent integration is separate."""
from __future__ import annotations
import http.client
import ipaddress
import socket
import urllib.parse
import urllib.request


def validate_source_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Sources require an HTTP(S) URL without embedded credentials")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Sources must use public Internet destinations")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return  # Resolve and pin DNS at connection time, including every redirect.
    if not address.is_global or address.is_multicast:
        raise ValueError("Sources must use public Internet destinations")


def _public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    host, port = address
    answers = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(item[4][0]).is_global or ipaddress.ip_address(item[4][0]).is_multicast for item in answers):
        raise OSError("Source destination resolved to a blocked network")
    error = None
    for family, kind, protocol, _, endpoint in answers:
        connection = socket.socket(family, kind, protocol)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connection.settimeout(timeout)
            if source_address:
                connection.bind(source_address)
            connection.connect(endpoint)  # Numeric, already-vetted endpoint: no second DNS lookup.
            return connection
        except OSError as exc:
            error = exc
            connection.close()
    raise error or OSError("Source connection failed")


class _PublicHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self._create_connection = _public_connection
        super().connect()


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        self._create_connection = _public_connection
        super().connect()  # TLS still authenticates the original hostname/SNI.


class PublicHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request):
        validate_source_url(request.full_url)
        return self.do_open(_PublicHTTPConnection, request)


class PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        validate_source_url(request.full_url)
        return self.do_open(_PublicHTTPSConnection, request, context=self._context)


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_source_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_handlers():
    # A proxy would resolve the final hostname itself, defeating destination pinning.
    return [urllib.request.ProxyHandler({}), PublicHTTPHandler(), PublicHTTPSHandler()]
