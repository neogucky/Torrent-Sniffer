"""Extract browser context from copied request headers without replaying the request."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

BROWSER_HEADERS = {
    "user-agent": "User-Agent",
    "accept": "Accept",
    "accept-language": "Accept-Language",
    "sec-ch-ua": "Sec-CH-UA",
    "sec-ch-ua-mobile": "Sec-CH-UA-Mobile",
    "sec-ch-ua-platform": "Sec-CH-UA-Platform",
}


def validate_browser_headers(headers: dict[str, str]) -> dict[str, str]:
    result = {}
    for name, value in headers.items():
        canonical = BROWSER_HEADERS.get(name.lower())
        if not canonical:
            raise ValueError(
                "Unsupported browser header. Paste the full request headers."
            )
        if canonical in result:
            raise ValueError(
                "A browser header appears more than once; copy one request only."
            )
        if (
            not value.strip()
            or len(value) > 2048
            or any(ord(char) < 32 or ord(char) > 126 for char in value)
        ):
            raise ValueError(
                "Browser header values must be nonempty, single-line text of at most 2048 characters."
            )
        result[canonical] = value.strip()
    return result


def _origin(value: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError
        return (
            parsed.scheme.lower(),
            parsed.hostname.lower(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except ValueError:
        raise ValueError("Provide a valid source URL.") from None


def extract_request_headers(
    value: str, base_url: str | None = None
) -> tuple[str, dict[str, str]]:
    """Return the Cookie value and allowed context; callers validate cookie syntax."""
    value = value.replace("\r\n", "\n")
    if (
        not value
        or len(value) > 32768
        or any(
            (ord(char) < 32 and char not in "\n\t") or ord(char) > 126 for char in value
        )
    ):
        raise ValueError(
            "Paste request headers as plain text, one name: value pair per line."
        )
    value = value.strip()
    if re.match(r"(?:curl\b|fetch\s*\(|HTTP/)", value, re.I):
        raise ValueError(
            "Copy Request Headers, not a response, Copy as cURL, or Copy as fetch command."
        )
    lines = value.split("\n")
    request = re.fullmatch(r"[A-Z]+\s+(\S+)\s+HTTP/(?:1\.[01]|[23](?:\.0)?)", lines[0])
    origins = []
    expected = _origin(base_url) if base_url else None
    if request:
        target = request.group(1)
        if "://" in target:
            origins.append(_origin(target))
        lines = lines[1:]
    headers: dict[str, str] = {}
    cookies = []
    authority = None
    scheme = expected[0] if expected else "https"
    ended = False
    for line in lines:
        if not line.strip():
            ended = True
            continue
        if ended:
            raise ValueError(
                "Paste only the request headers, without a request body or a second request."
            )
        match = re.fullmatch(r"(:?[!#$%&'*+\-.^_`|~0-9A-Za-z]+):[ \t]*(.*)", line)
        if not match:
            raise ValueError(
                "Each request header needs a name and value on the same line. Use Copy Request Headers or View source."
            )
        name, content = match.group(1).lower(), match.group(2).strip()
        if name in {"set-cookie", ":status"}:
            raise ValueError(
                "These are response headers. Copy the browser's Request Headers instead."
            )
        if name == "cookie":
            cookies.append(content)
        elif name in BROWSER_HEADERS:
            if name in headers:
                raise ValueError(
                    "A browser header appears more than once; copy one request only."
                )
            headers[name] = content
        elif name in {"host", ":authority"}:
            if authority is not None and authority.lower() != content.lower():
                raise ValueError("The pasted request contains conflicting hostnames.")
            authority = content
        elif name == ":scheme":
            if content not in {"http", "https"}:
                raise ValueError("The pasted request has an unsupported scheme.")
            scheme = content
    if authority is not None:
        if not authority or any(char in authority for char in "/?#@"):
            raise ValueError("The pasted request has an invalid hostname.")
        origins.append(_origin(f"{scheme}://{authority}"))
    if expected and any(origin != expected for origin in origins):
        raise ValueError(
            "These request headers belong to a different source. Copy a request from the configured source URL."
        )
    if len(set(origins)) > 1:
        raise ValueError("The pasted request contains conflicting hostnames.")
    if not cookies or not all(cookies):
        raise ValueError("Cookie is missing.")
    if not headers.get("user-agent"):
        raise ValueError("User-Agent is missing.")
    cookie = "; ".join(cookies)
    if len(cookie) > 16384:
        raise ValueError("The Cookie header is too long; copy one source request only.")
    return cookie, validate_browser_headers(headers)
