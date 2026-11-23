"""Links and paths users store or pages navigate to (no network request)."""

from urllib.parse import urlsplit


def external_url(value: str | None, *, allow_relative: bool = False) -> str | None:
    """A stored link: an HTTP or HTTPS URL without credentials, or (with
    ``allow_relative``) a path on this site. Backslashes and control
    characters are refused anywhere: a browser reads "/\\host" as "//host"."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        if (
            len(value) > 2048
            or "\\" in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError()
        if allow_relative and same_site_path(value) == value:
            return value
        url = urlsplit(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
        ):
            raise ValueError()
        _ = url.port
    except ValueError:
        raise ValueError(
            "Use an HTTP or HTTPS URL without embedded credentials or control characters"
        ) from None
    return value


def same_site_path(value: str | None) -> str | None:
    """``value`` when it is a path on this site a browser cannot read as
    another site's, otherwise None (the caller falls back to a fixed page).

    Browsers resolve dot segments, including percent-encoded ones, before they
    navigate, so a path such as ``/.//host`` would become the network-path
    reference ``//host``; such paths, encoded separators and backslashes are
    refused.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    path = raw.split("?", 1)[0].split("#", 1)[0]
    if (
        raw.startswith("/")
        and not raw.startswith("//")
        and "://" not in raw
        and "\\" not in raw
        and not any(ord(c) < 32 or ord(c) == 127 for c in raw)
        and not any(code in path.lower() for code in ("%2e", "%2f", "%5c"))
        and not any(segment in {".", ".."} for segment in path.split("/"))
    ):
        return raw
    return None
