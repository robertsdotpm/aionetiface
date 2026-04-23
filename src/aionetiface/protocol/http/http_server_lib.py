"""Lightweight async HTTP server and REST-dispatch helpers."""
import inspect
import re
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Tuple
from ...utility.utils import fstr, re_unescape, dict_merge, to_b, to_s, to_n, in_range, log_exception
from .http_client_lib import http_parse_headers
from ...net.daemon import Daemon

aionetiface_PORT = 12333
aionetiface_CORS = ["null", "http://127.0.0.1"]
aionetiface_MIME = [[dict, "json"], [bytes, "binary"], [str, "text"]]


# Support passing in GET params using path seperators.
# Ex: /timeout/10/sub/all -> {'timeout': '10', 'sub': 'all'}
def get_params(field_names: List[str], url_path: str) -> Dict[str, str]:
    """Extract named key/value pairs from a slash-separated URL path and return them as a dict."""
    # Return empty.
    if not field_names:
        return {}

    # Build regex match string.
    p = ""
    for field in field_names:
        # Escape any regex-specific characters.
        as_literal = re.escape(field)
        as_literal = as_literal.replace("/", "")

        # (/ field name / non dir chars )
        # All are marked as optional.
        p += fstr("(?:/({0})/([^/]+))|", (as_literal,))

    # Repeat to match optional instances of the params.
    p = fstr("(?:{0})+", (p[:-1],))

    # Convert the marked pairs to a dict.
    params = {}
    safe_url = re.escape(url_path)
    results = re.findall(p, safe_url)
    if len(results):
        results = results[0]
        for i in range(0, int(len(results) / 2)):
            # Every 2 fields is a named value.
            name = results[i * 2]
            value = results[(i * 2) + 1]
            value = re_unescape(value)

            # Param not set.
            if name == "":
                continue

            # Save by name.
            name = re_unescape(name)
            params[name] = value

    # Return it for use.
    return params


def api_closure(url_path: str) -> Callable[..., Any]:
    """Return an api() callable that matches url_path against a regex and returns a named-field dict."""
    # Fields list names a p result and is in a fixed order.
    # Get names matches named values and is in a variable order.
    def api(p, field_names=None, get_names=None):
        """Match regex p against the captured url_path and map groups to field_names or get_names."""
        if field_names is None:
            field_names = []
        if get_names is None:
            get_names = []
        out = re.findall(p, url_path)
        as_dict = {}
        if len(out):
            if isinstance(out[0], tuple):
                out = out[0]

            if len(field_names):
                for i in range(min(len(out), len(field_names))):
                    as_dict[field_names[i]] = out[i]
            else:
                as_dict["out"] = out

        params = get_params(get_names, url_path)
        if len(params) and len(as_dict):
            return dict_merge(params, as_dict)
        return as_dict

    return api


# p = {}, optional = [ named ... ]
# default = [ matching values ... ]
def set_defaults(p: Dict[str, Any], optional: List[str], default: List[Any]) -> None:
    """Fill in missing keys in p from the parallel default list for any optional parameter names."""
    # Set default param values.
    for i, named in enumerate(optional):
        if named not in p:
            p[named] = default[i]


class ParseHTTPRequest(BaseHTTPRequestHandler):
    """Parse a raw HTTP request byte string using BaseHTTPRequestHandler."""

    def __init__(self, request_text: bytes) -> None:
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        http_parse_headers(self)

    def send_error(self, code: int, message: Optional[str] = None) -> None:
        """Record the error code and message instead of sending an HTTP response."""
        self.error_code = code
        self.error_message = message


# Create a HTTP server response.
# Supports JSON or binary.
def http_res(
    payload: Any, mime: str, req: Any, client_tup: Optional[Tuple[str, int]] = None
) -> bytes:
    """Serialise payload to the given MIME type and return a complete HTTP/1.1 200 response as bytes."""
    # Support JSON responses.
    if mime == "json":
        # Document content is a JSON string with good indenting.
        payload = json.dumps(payload, indent=4, sort_keys=True)
        payload = to_b(payload)
        content_type = b"application/json"

    # Support binary responses.
    if mime == "binary":
        payload = to_b(payload)
        content_type = b"application/octet-stream"

    if mime == "text":
        payload = to_b(payload)
        content_type = b"text/html"

    # CORS policy header line.
    allow_origin = b"Access-Control-Allow-Origin: %s" % (to_b(req.hdrs["Origin"]))

    # List of HTTP headers to send for our el8 web server.
    res = b"HTTP/1.1 200 OK\r\n"
    res += b"%s\r\n" % (allow_origin)
    if client_tup is not None:
        res += b"x-client-tup: %s:%d\r\n" % (to_b(client_tup[0]), client_tup[1])
    else:
        res += b"x-client-tup: unknown\r\n"
    res += b"Content-Type: %s\r\n" % (content_type)
    res += b"Connection: close\r\n"
    res += b"Content-Length: %d\r\n\r\n" % (len(payload))
    res += payload

    return res


async def send_json(
    a_dict: Dict[str, Any], req: Any, client_tup: Tuple[str, int], pipe: Any
) -> None:
    """Send a_dict as a JSON HTTP response to client_tup and close the pipe."""
    remote_client_tup = None
    if "client_tup" in a_dict:
        remote_client_tup = a_dict["client_tup"]

    res = http_res(a_dict, "json", req, remote_client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()


async def send_binary(
    out: bytes, req: Any, client_tup: Tuple[str, int], pipe: Any
) -> None:
    """Send out as an octet-stream HTTP response to client_tup and close the pipe."""
    res = http_res(out, "binary", req, client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()


async def send_text(out: str, req: Any, client_tup: Tuple[str, int], pipe: Any) -> None:
    """Send out as a text/html HTTP response to client_tup and close the pipe."""
    res = http_res(out, "text", req, client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()


async def rest_service(
    msg: bytes,
    client_tup: Tuple[str, int],
    pipe: Any,
    api_closure: Callable[..., Any] = api_closure,
) -> Optional[Any]:
    """Parse an incoming HTTP message, enforce CORS, handle pre-flight requests, and return the parsed req object."""
    # Parse http request.
    try:
        req = ParseHTTPRequest(msg)
    except ValueError:
        log_exception()
        return None

    # Deny restricted origins.
    if req.hdrs["Origin"] not in aionetiface_CORS:
        resp = {"msg": "Invalid origin.", "error": 5}
        await send_json(resp, req, client_tup, pipe)
        return None

    # Implements 'pre-flight request checks.'
    cond_1 = "Access-Control-Request-Method" in req.hdrs
    cond_2 = "Access-Control-Request-Headers" in req.hdrs
    if cond_1 and cond_2:
        # CORS policy header line.
        allow_origin = "Access-Control-Allow-Origin: %s" % (req.hdrs["Origin"])

        # HTTP response.
        out = b"HTTP/1.1 200 OK\r\n"
        out += b"Content-Length: 0\r\n"
        out += b"Connection: keep-alive\r\n"
        out += b"Access-Control-Allow-Methods: POST, GET, DELETE\r\n"
        out += b"Access-Control-Allow-Headers: *\r\n"
        out += b"%s\r\n\r\n" % (to_b(allow_origin))
        await pipe.send(out, client_tup)
        return None

    # Critical URL path part is encoded.
    url_parts = urllib.parse.urlparse(req.path)
    url_path = urllib.parse.unquote(url_parts.path)
    url_query = urllib.parse.parse_qs(url_parts.query)
    req.url = {"parts": url_parts, "path": url_path, "query": url_query}

    req.api = api_closure(url_path)
    return req


# Routes a URL path to named and unnamed parameters based on scheme definitions.
# Each scheme entry is [name] or [name, default] or [name, default, regex].
def api_route_closure(url_path: str) -> Callable[..., Any]:
    """Return an api() callable that maps slash-separated URL segments to scheme-defined named and positional params."""
    # Fields list names a p result and is in a fixed order.
    # Get names matches named values and is in a variable order.
    def api(schemes):
        """Match url_path segments against schemes and return (named_dict, positional_dict)."""
        # Break up the URL based on slashes.
        out = re.findall(r"(?:/([^/]+))", url_path)
        as_dict = {}
        unnamed = {}
        out = list(out)

        # Generate a list of matches for schemes across out list.
        def in_schemes(v):
            """Return (scheme_index, value, matched) indicating whether URL segment v matches any scheme entry."""
            for i in range(len(schemes)):
                # Use regex to check value.
                scheme = schemes[i]
                if len(scheme) == 3:
                    if scheme[2] == "*":
                        return (i, v, True)

                    if re.match(scheme[2], v) is not None:
                        return (i, v, True)
                    return (i, scheme[1], True)

                # Compare value only.
                if v == scheme[0]:
                    return (i, v, True)

            return (None, v, False)

        # Supports routing via named params with regex and defaults.
        # Unnamed positional params are returned in another dict.
        i = 0
        schemes_matches = [in_schemes(o) for o in out]
        while len(schemes_matches):
            # Get scheme for associated match.
            scheme_p, val_match, cur_match = schemes_matches[0]
            if scheme_p is not None:
                cur_scheme = schemes[scheme_p]
            else:
                cur_scheme = None

            # Unnamed positional argument.
            if not cur_match:
                unnamed[i] = val_match
                i += 1
                schemes_matches.pop(0)
                continue

            # Don't compare next element.
            if len(schemes_matches) >= 2:
                # Allow checking next element.
                scheme_p, next_val_match, next_match = schemes_matches[1]

                # Next doesn't match so take as a value to this.
                if scheme_p is None and not next_match:
                    val_match = next_val_match
                    if len(cur_scheme) > 1:
                        cur_scheme[1] = next_val_match

                    schemes_matches.pop(0)

            # Substitute a default value.
            if len(cur_scheme) > 1:
                val = cur_scheme[1]
            else:
                val = val_match

            # Set the match.
            as_dict[cur_scheme[0]] = val
            schemes_matches.pop(0)

        return as_dict, unnamed

    return api


class RESTD(Daemon):
    """Daemon subclass that automatically discovers decorated REST API handlers and dispatches HTTP requests to them."""

    def __init__(self) -> None:
        super().__init__()

        # Get a list of function methods for this class.
        # This is needed because sub-classes dynamically add methods.
        methods = [
            member
            for member in [getattr(self, attr) for attr in dir(self)]
            if inspect.ismethod(member)
        ]

        # Loop over class instance methods.
        # Build a list of decorated methods that will form REST API.
        self.apis = {"GET": [], "POST": [], "DELETE": []}
        for f in methods:
            if "REST__" in f.__name__[:7]:
                self.apis[f.http_method].append(f)

    @staticmethod
    def rest_api_decorator(f: Any, args: Any) -> Any:
        """Tag function f with a REST__ prefix and store its route scheme args so it can be discovered at runtime."""
        # Allow this method to be looked up.
        f.__name__ = "REST__" + f.__name__

        # Simulate default arguments.
        # Schemes passed in as f(scheme, ...)
        # rather than f([scheme, ...]).
        fargs = []
        for scheme in args:
            fargs.append(scheme)

        # Store the args in the function.
        f.args = fargs

        # Call original function.
        return f

    @staticmethod
    def GET(*args: Any, **kw: Any) -> Callable[..., Any]:
        """Decorator that registers the decorated function as a GET route with the given URL scheme args."""
        def decorate(f):
            """Tag f as a GET handler and register it with the REST dispatcher."""
            # Save HTTP method.
            f.http_method = "GET"
            return RESTD.rest_api_decorator(f, args)

        return decorate

    @staticmethod
    def POST(*args: Any, **kw: Any) -> Callable[..., Any]:
        """Decorator that registers the decorated function as a POST route with the given URL scheme args."""
        def decorate(f):
            """Tag f as a POST handler and register it with the REST dispatcher."""
            # Save HTTP method.
            f.http_method = "POST"
            return RESTD.rest_api_decorator(f, args)

        return decorate

    @staticmethod
    def DELETE(*args: Any, **kw: Any) -> Callable[..., Any]:
        """Decorator that registers the decorated function as a DELETE route with the given URL scheme args."""
        def decorate(f):
            """Tag f as a DELETE handler and register it with the REST dispatcher."""
            # Save HTTP method.
            f.http_method = "DELETE"
            return RESTD.rest_api_decorator(f, args)

        return decorate

    # Todo: $_GET from ?...
    async def msg_cb(self, msg: bytes, client_tup: Tuple[str, int], pipe: Any) -> None:
        """Parse an incoming HTTP request, route it to the best matching REST API method, and send the reply."""
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe, api_route_closure)

        # Receive any HTTP payload data.
        body = b""
        payload_len = 0
        if "Content-Length" in req.hdrs:
            # Content len must not exceed msg len.
            payload_len = to_n(req.hdrs["Content-Length"])
            if in_range(payload_len, [1, len(msg)]):
                # Last content-len bytes == payload.
                body = msg[-payload_len:]

        # Convert body payload to json.
        if "Content-Type" in req.hdrs:
            if req.hdrs["Content-Type"] == "application/json":
                if payload_len:
                    body = json.loads(to_s(body))

        # Call all matching API routes.
        v = None
        positional_no = 100
        best_matching_api = None
        for api in self.apis[req.command]:
            named, positional = req.api(api.args)

            # Matches /.
            if len(self.apis[req.command]) == 1:
                pass
            else:
                # Not a matching API method.
                if len(named) != len(api.args):
                    continue

            # Find best matching API method.
            if len(positional) < positional_no:
                best_matching_api = api
                positional_no = len(positional)

                # HTTP request info for API method.
                v = {
                    "req": req,
                    "name": named,
                    "pos": positional,
                    "client": client_tup,
                    "body": body,
                }

        # Call matching API method.
        if best_matching_api is not None:
            # Get response from wrapped function.
            # Capture any exceptions in the reply.
            try:
                resp = await best_matching_api(v, pipe)
            except (OSError, ValueError, RuntimeError) as e:
                resp = {
                    "error": "Exception",
                    "msg": str(e),
                }

            # Match output types to the write mime headers.
            for out_info in aionetiface_MIME:
                if isinstance(resp, out_info[0]):
                    # Full HTTP reply to client.
                    buf = http_res(resp, out_info[1], req, client_tup)

                    # Send it back to the client.
                    await pipe.send(buf, client_tup)
                    break
