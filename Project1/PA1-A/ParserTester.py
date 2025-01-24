from enum import Enum
import re

class ParseError(Enum):
    NOTIMPL = 1
    BADREQ = 2

notimplreq = (ParseError.NOTIMPL, None, None, None, None)
badreq = (ParseError.BADREQ, None, None, None, None)

http_methods = {
    "GET",        
    "POST",       
    "PUT",        
    "DELETE",     
    "PATCH",
    "HEAD",       
    "OPTIONS",    
    "CONNECT",    
    "TRACE"       
}

def parse_request(request: bytes):  
    try:
        request_str = request.decode('utf-8')

        # Split the request into lines
        lines = request_str.split("\r\n")
        
        # Parse the request line
        request_line = lines[0]
        method, url, http_version = request_line.split()

        if method.upper() not in http_methods:
            return badreq
        if method.upper() != "GET":
            # raise ValueError("501 Not Implemented")
            return notimplreq
        
        # url_pattern = r"^http://.+/$"
        url_pattern = r"^http://[a-zA-Z0-9.-]+(:[0-9]+)?/.*$"
        # if not url.startswith("http://"):
        #     return badreq
        # if not url.endswith("/"):
        #     return badreq
        if not re.match(url_pattern, url):
            return badreq
        
        if http_version != "HTTP/1.0":
            return ValueError("400 Bad Request")
        
        # Parse headers
        header_pattern = r"^([^ ]+): (.*)$"
        headers = {}
        for line in lines[1:]:
            if not line.strip():
                break
            match = re.match(header_pattern, line)
            if match:
                headers[match.group(1).encode()] = match.group(2).encode()
            else:
                # raise ValueError("400 Bad Request")
                return badreq
        
        return {
            "method": method,
            "url": url,
            "http_version": http_version,
            "headers": headers if headers else {}
        }
    except ValueError:
        # raise ValueError("400 Bad Request")
        return badreq    
    
def parse_url(url):
    if "://" in url:
        protocol, url = url.split("://", 1)

    if "/" in url:
        hostname, path = url.split("/", 1)
        path = "/" + path
    else:
        hostname = url
        path = "/"
    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    else:
        port = 80

    return {
        "hostname": hostname,
        "port": port,
        "path": path
    }

requests = [
    # # Just a kick the tires test
    # (b'GET http://www.google.com/ HTTP/1.0\r\n\r\n', (None, b'www.google.com', 80, b'/', {})),
    # # 102.2) Test handling of malformed request lines [0.5 points]
    (b'HEAD http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n', notimplreq),
    # (b'POST http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n', notimplreq),
    # (b'GIBBERISH http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n', badreq),
    # # 102.3) Test handling of malformed header lines [0.5 points]
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nthis is not a header\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection : close\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection:close\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0\r\ngibberish\r\n\r\n', badreq),
    # # 102.4) Test handling of malformed URIs [0.5 points]
    # (b'GET www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu HTTP/1.0\r\n\r\n', badreq),
    # (b'GET /cs4480/simple.html HTTP/1.0\r\n\r\n', badreq),
    # (b'GET gibberish HTTP/1.0\r\n\r\n', badreq),
    # # 102.5) Test handling of wrong HTTP versions
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.1\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html 1.0\r\n\r\n', badreq),
    # (b'GET http://www.flux.utah.edu/cs4480/simple.html gibberish\r\n\r\n', badreq),
    # 103.5) Requests should include the specified headers [0.5 points]
    # (b'GET http://localhost:8080/simple.html HTTP/1.0\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0\r\n\r\n',
    #   (None, b'localhost', 8080, b'/simple.html', {b'Connection': b'close', b'User-Agent': b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Firefox/50.0'}))
]

for request, expected in requests:
    print(f"Testing {request}")
    parsedrequest = parse_request(request)
    # parsedurl = parse_url(parsedrequest["url"])
    # parsed = (None, parsedurl["hostname"].encode('utf-8'), parsedurl["port"], parsedurl["path"].encode('utf-8'), parsedrequest["headers"])
    # assert parsed == expected, f"{request} yielded {parsed} instead of {expected}"
    if isinstance(parsedrequest, dict):
        parsedurl = parse_url(parsedrequest["url"])
        parsed = (None, parsedurl["hostname"].encode('utf-8'), parsedurl["port"], parsedurl["path"].encode('utf-8'), parsedrequest["headers"])
    else:
        parsed = parsedrequest

    assert parsed == expected, f"{request} yielded {parsed} instead of {expected}"
print('All tests passed!')