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
_TOKEN = r":?[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_HEADER_LINE = re.compile(rf"({_TOKEN}):[ \t]*(.*)\Z")
_HEADER_NAME = re.compile(rf"({_TOKEN}):?\Z")
_COPY_NAMES = set(BROWSER_HEADERS) | {
    ":authority",
    ":method",
    ":path",
    ":scheme",
    ":status",
    "accept-encoding",
    "authorization",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "dnt",
    "host",
    "origin",
    "pragma",
    "priority",
    "proxy-authorization",
    "referer",
    "sec-gpc",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "set-cookie",
    "te",
    "upgrade-insecure-requests",
}
# Quoted values and browser comments are opaque. A URL colon is not a header
# boundary: a flattened header separator requires whitespace after the colon.
_FLAT_BOUNDARY = re.compile(
    rf'"(?:\\.|[^"\\])*"|\([^)]*\)|[ \t]+(?P<name>{_TOKEN}):(?=[ \t])'
)


def normalise_request_headers(value: str) -> str:
    """Repair common DevTools clipboard layouts without decoding header values."""
    value = value.removeprefix("\ufeff")
    if len(value) > 32768 or any(
        (ord(char) < 32 and char not in "\r\n\t")
        or (ord(char) > 126 and char not in "\u2028\u2029\u00a0")
        for char in value
    ):
        raise ValueError("Paste request headers as plain text.")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("\u2028", "\n").replace("\u2029", "\n")
    value = value.replace("\u00a0", " ")
    if "\n" not in value and "\\n" in value:
        value = value.replace("\\r\\n", "\n").replace("\\n", "\n")
    if len(value) > 32768:
        raise ValueError("Request headers are too long; copy one request only.")

    lines = []
    for line in value.strip().split("\n"):
        cells = [cell.strip() for cell in line.split("\t")]
        if len(cells) > 1 and all(_HEADER_LINE.fullmatch(cell) for cell in cells):
            lines.extend(cells)
        elif (
            len(cells) > 1
            and len(cells) % 2 == 0
            and all(_HEADER_NAME.fullmatch(cell) for cell in cells[::2])
        ):
            lines.extend(
                f"{name.rstrip(':')}: {content}"
                for name, content in zip(cells[::2], cells[1::2])
            )
        else:
            lines.append(line)
    if len(lines) == 1 and (
        _HEADER_LINE.fullmatch(lines[0])
        or re.match(r"[A-Z]+\s+\S+\s+HTTP/[\d.]+\s", lines[0])
    ):
        value = _FLAT_BOUNDARY.sub(
            lambda match: f"\n{match['name']}:" if match["name"] else match[0],
            lines[0],
        )
        lines = value.split("\n")

    result = []
    paired = False
    has_request_line = bool(
        lines and re.fullmatch(r"[A-Z]+\s+\S+\s+HTTP/[\d.]+", lines[0].strip())
    )
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        name = _HEADER_NAME.fullmatch(line)
        if name:
            following = index + 1
            while following < len(lines) and not lines[following].strip():
                following += 1
            content = lines[following].strip() if following < len(lines) else ""
            next_header = _HEADER_LINE.fullmatch(content)
            next_name = _HEADER_NAME.fullmatch(content)
            is_next_header = (
                next_header and next_header[1].lower() in _COPY_NAMES
            ) or (next_name and next_name[1].lower() in _COPY_NAMES)
            if content and not is_next_header:
                result.append(f"{name[1]}: {content}")
                paired = True
                index = following + 1
                continue
            if name[1].lower() in _COPY_NAMES:
                result.append(f"{name[1]}:")
                paired = True
                index += 1
                continue
        if line or not paired or has_request_line:
            result.append(line)
        index += 1
    return "\n".join(result)


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
    value = normalise_request_headers(value)
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
        match = _HEADER_LINE.fullmatch(line)
        if not match:
            raise ValueError(
                "Header layout is incomplete. Copy the request headers again."
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
