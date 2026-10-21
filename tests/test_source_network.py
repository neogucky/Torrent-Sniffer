import socket
from email.message import Message
from unittest.mock import Mock, patch
import pytest
from app import source_network as network


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/", "http://10.0.0.1/", "http://localhost/", "http://printer.local/", "file:///etc/passwd", "ftp://example.com/", "http://user:pass@example.com/"])
def test_private_and_non_http_destinations_rejected(url):
    with pytest.raises(ValueError):
        network.validate_source_url(url)


def test_dns_rebinding_to_private_network_is_rejected_before_socket_creation():
    answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with patch.object(socket, "getaddrinfo", return_value=answer), patch.object(socket, "socket") as constructor:
        with pytest.raises(OSError, match="blocked network"):
            network._public_connection(("source.example", 443), 1)
        constructor.assert_not_called()


def test_mixed_public_and_private_dns_answers_are_rejected():
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ["93.184.216.34", "169.254.169.254"]]
    with patch.object(socket, "getaddrinfo", return_value=answers), patch.object(socket, "socket") as constructor:
        with pytest.raises(OSError):
            network._public_connection(("source.example", 443), 1)
        constructor.assert_not_called()


def test_connection_uses_the_vetted_numeric_endpoint_without_resolving_again():
    answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    connection = Mock()
    with patch.object(socket, "getaddrinfo", return_value=answer) as resolver, patch.object(socket, "socket", return_value=connection):
        assert network._public_connection(("source.example", 443), 2) is connection
        resolver.assert_called_once()
        connection.connect.assert_called_once_with(("93.184.216.34", 443))


def test_redirect_to_metadata_is_rejected():
    request = network.urllib.request.Request("https://source.example/")
    with pytest.raises(ValueError):
        network.PublicRedirect().redirect_request(request, None, 302, "", Message(), "http://169.254.169.254/latest/meta-data/")


def test_https_handler_uses_the_supported_python_connection_interface():
    handler = network.PublicHTTPSHandler()
    request = network.urllib.request.Request("https://source.example/")
    with patch.object(handler, "do_open", return_value="response") as open_connection:
        assert handler.https_open(request) == "response"
        open_connection.assert_called_once_with(network._PublicHTTPSConnection, request, context=handler._context)


def test_pinned_https_connection_keeps_original_tls_hostname():
    context = Mock()
    transport = Mock()
    connection = network._PublicHTTPSConnection("source.example", context=context)
    with patch.object(network, "_public_connection", return_value=transport):
        connection.connect()
    context.wrap_socket.assert_called_once_with(transport, server_hostname="source.example")
