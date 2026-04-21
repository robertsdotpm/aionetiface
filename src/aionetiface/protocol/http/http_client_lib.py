import copy
from http.client import HTTPResponse
import json
from ...net import *
from ...net.pipe.pipe import *
from ...net.address import *

HTTP_HEADERS = [
    [b"User-Agent", b"curl/7.54.0"],
    [b"Origin", b"null"],
    [b"Accept", b"*/*"]
]

def http_req_buf(af, host, path=b"/", method=b"GET", payload=b"", headers=None):
    # Format headers.
    hdrs = {}
    if headers is None:
        headers = HTTP_HEADERS
    else:
        headers += HTTP_HEADERS

    # Raw http request.
    # Very important: 1.0 is used to disable 'chunked encoding.'
    # Chunked encoding overly complicates processing HTTP responses.
    buf  = b"%s %s HTTP/1.0\r\n" % (to_b(method), to_b(path))
    if af == IP4:
        host = to_b(host)
    else:
        host = to_b(fstr("[{0}]", (to_s(host),)))
    buf += b"Host: %s\r\n" % (host)
    for header in headers:
        n, v = header

        # Don't add host header twice.
        if n.lower() == b"host":
            continue
        
        # Skip duplicate headers.
        if n not in hdrs:
            buf += b"%s: %s\r\n" % (n, v)
            hdrs[n] = 1

    # Add content length for payload.
    if payload is not None:
        buf += to_b(fstr("Content-Length: {0}\r\n", (len(payload),)))
    
    # Terminate headers.
    buf = buf[:-2]
    assert(buf[-1] not in [b'\r', b'\n'])
    buf += b"\r\n\r\n"

    # Append payload (if any.)
    if payload is not None:
        buf += to_b(payload)

    return buf

def http_parse_headers(self):
    # Get headers from named pair list.
    hdrs = {}
    for named_pair in self.headers._headers:
        name, value = named_pair
        hdrs[name] = value
        hdrs[name.lower()] = value

    # Set origin.
    if 'Origin' not in hdrs:
        hdrs['Origin'] = 'null'
        hdrs['origin'] = 'null'

    # Save header list.
    self.hdrs = hdrs

class ParseHTTPResponse(HTTPResponse):
    def __init__(self, resp_text):
        self.resp_len = len(resp_text)
        self.fp = self.sock = FakeSocket(resp_text)
        super().__init__(self.sock)
        self.begin()
        http_parse_headers(self)

        te = "Transfer-Encoding"
        if te in self.hdrs:
            if self.hdrs[te] == "chunked":
                raise Exception("chunked encoding not supported!")

    def out(self):
        return self.read(self.resp_len)
    
def get_hdr(name, hdrs):
    # Hdrs none probably.
    if not isinstance(hdrs, list):
        return (-1, None)
    
    # Look for particular HTTP header.
    for index, hdr in enumerate(hdrs):
        if hdr[0].lower() == name.lower():
            return (index, hdr[1])
        
    # Not found.
    return (-1, None)

async def url_res(route, url, timeout=3):
    """
    Break up a URL into its host, port, and file path, and resolve the
    domain for use with networking code that makes the HTTP request.
    """
    # Split URL into host and port.
    port = 80
    url_parts = urllib.parse.urlparse(url)
    host = netloc = url_parts.netloc
    path = url_parts.path

    # Overwrite default port 80.
    if ":" in netloc:
        host, port = netloc.split(":")
        port = int(port)

    # Resolve domain of URL.
    dest = (
        host,
        port,
    )

    # Return URL parts.
    return {
        "host": host,
        "port": port,
        "path": path,
        "dest": dest
    }


# Web payload decorators
def Payload(f, url=None, body=b""):
    if url is None:
        url = {}
    async def wrapper(path, hdrs=None):
        if hdrs is None:
            hdrs = []
        return await f(path=path, hdrs=hdrs, url=url, body=body)

    return wrapper

# Returns pipe, ParseHTTPResponse
async def do_web_req(addr, http_buf, do_close, route, conf=NET_CONF):
    log(fstr("{0}", (addr,)))

    # Open TCP connection to HTTP server.
    p = None
    try:
        p = await Pipe(TCP, addr, route, conf=conf).connect()
    except (OSError, ConnectionError, asyncio.TimeoutError):
        log_exception()
        p = None

    # Error return empty.
    if p is None:
        return None, None
    try:
        p.subscribe(SUB_ALL)
        await p.send(http_buf, addr)
    except (OSError, ConnectionError):
        log_exception()
        await p.close()
        return None, None


    # Read TCP stream until headers contain Content-Length
    out = b""
    content_len = 0
    hdr_ended = False
    headers = b""
    content = b""
    while True:
        buf = await p.recv(SUB_ALL, timeout=conf['recv_timeout'])
        if not buf:
            break
        out += buf

        # Check if headers end and find Content-Length.
        # HTTP/1.0: break early only when Content-Length is known; otherwise
        # the connection close (buf == b"") signals end-of-body.
        if b"\r\n\r\n" in out:
            hdr_ended = True
            content_len_search = re.search(b"[cC]ontent-[lL]ength: *([0-9]+)", out)
            if content_len_search:
                content_len = int(content_len_search.group(1))
                break

    # Split raw response into header block and initial body bytes.
    if hdr_ended:
        parts = re.split(b"\r\n\r\n", out, maxsplit=1)
        headers = parts[0]
        content = parts[1] if len(parts) > 1 else b""

    # Read remaining content if a Content-Length told us how much to expect.
    if content_len:
        while len(content) < content_len:
            buf = await p.recv(SUB_ALL, timeout=conf['recv_timeout'])
            if not buf:
                break
            content += buf

    # Some connections may be left open.
    if do_close:
        await p.close()
        p = None

    # Parse HTTP response.  Bail out cleanly if no headers were received
    # (e.g. connection dropped before the blank line separator arrived).
    if not hdr_ended:
        return None, None

    out = ParseHTTPResponse(headers)

    if content:
        out.out = lambda: content

    return p, out

class WebCurl():
    """
    Minimal async HTTP client.

    Usage:
        curl = WebCurl(addr, route, do_close=0)
        resp = await curl.vars(url_params, body_payload).get("/")
        resp.pipe   # open TCP connection, if do_close=0
        resp.out    # raw response body bytes
        resp.info   # parsed ParseHTTPResponse object
    """
    def __init__(self, addr, route, throttle=0, do_close=1, hdrs=None):
        self.addr = addr
        self.route = route
        self.url_params = {}
        self.hdrs = hdrs if hdrs is not None else []
        self.body = b""
        self.req_buf = self.out = None
        self.path = self.info = None
        self.throttle = throttle
        self.do_close = do_close

    # Returns a deep copy of this client for use in concurrent requests.
    def copy(self):
        route = copy.deepcopy(self.route)
        client = WebCurl(self.addr, route)
        client.url_params = self.url_params
        client.body = self.body
        client.path = self.path
        client.hdrs = self.hdrs
        client.info = self.info
        client.out = self.out
        client.req_buf = self.req_buf
        client.throttle = self.throttle
        client.do_close = self.do_close
        return client

    def vars(self, url_params=None, body=b""):
        # Avoid race conditions.
        client = self.copy()
        if url_params is None:
            url_params = {}

        # Url encode url params if set.
        if len(url_params):
            client.url_params = {
                "safe": urllib.parse.urlencode(url_params),
                "unsafe": url_params
            }

        client.body = body
        return client
    
    async def api(self, method, path, hdrs, conf):
        # New instance to avoid race conditions.
        client = self.copy()
        client.path = path
        client.hdrs = hdrs

        # Append url encoded path if present.
        if len(client.url_params):
            path += fstr('?{0}', (client.url_params["safe"],))

        # If payload is a dict convert to json buf.
        hdrs = hdrs or self.hdrs
        if isinstance(self.body, dict):
            client.body = json.dumps(client.body)
            hdrs.append([b"Content-Type", b"application/json"])

        # Build a HTTP request to send to server.
        af = client.route.af
        nic = client.route.interface
        req_buf = http_req_buf(
            af=af,
            host=client.addr[0],
            path=path,
            method=method,
            payload=client.body,
            headers=hdrs
        )

        # Save request for debugging.
        client.req_buf = req_buf

        # Throttle request.
        if self.throttle:
            await asyncio.sleep(client.throttle)

        # Make the HTTP request to the server.
        route = await client.route.bind()
        addr = await resolv_dest(af, client.addr, nic)
        ret = await async_wrap_errors(
            do_web_req(
                route=route,
                addr=addr, 
                http_buf=req_buf,
                do_close=client.do_close,
                conf=conf
            )
        )

        # Unpack ret value.
        pipe = info = None
        if ret is not None:
            pipe, info = ret

        # Save output.
        client.pipe = pipe
        if info is None:
            client.info = None
            client.out = b""
        else:
            client.out = info.out()
            client.info = info

        return client

    async def get(self, path, hdrs=None, conf=NET_CONF):
        return await self.api("GET", path, hdrs or [], conf)

    async def post(self, path, hdrs=None, conf=NET_CONF):
        return await self.api("POST", path, hdrs or [], conf)

    async def delete(self, path, hdrs=None, conf=NET_CONF):
        return await self.api("DELETE", path, hdrs or [], conf)