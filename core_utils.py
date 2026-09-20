from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import requests


def get_parameters(url):
    """Return unique GET parameter names while preserving blank values."""
    query = urlsplit(url).query
    params = parse_qsl(query, keep_blank_values=True)

    seen = set()
    result = []

    for name, _ in params:
        if name not in seen:
            seen.add(name)
            result.append(name)

    return result


def replace_parameter(url, parameter, value):
    """Replace one GET parameter without breaking URL encoding or path."""
    parts = urlsplit(url)

    params = parse_qsl(parts.query, keep_blank_values=True)

    replaced = False
    new_params = []

    for name, old_value in params:
        if name == parameter and not replaced:
            new_params.append((name, value))
            replaced = True
        else:
            new_params.append((name, old_value))

    new_query = urlencode(new_params, doseq=True)

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        new_query,
        parts.fragment
    ))


def create_session(headers=None):
    """Create a reusable HTTP session."""
    session = requests.Session()

    if headers:
        session.headers.update(headers)

    return session
