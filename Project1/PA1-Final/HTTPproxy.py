# Place your imports here
import re
import signal
from optparse import OptionParser
import sys
from socket import *
import threading

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

http_methods = [
    "GET",        
    "POST",       
    "PUT",        
    "DELETE",     
    "PATCH",
    "HEAD",       
    "OPTIONS",    
    "CONNECT",    
    "TRACE"       
]


class ProxyConfig:
    """ Shared configuration for the proxy server """
    def __init__(self):
        self.cache = {} 
        self.caching_on = False  
        self.blocklist = [] 
        self.blocklist_on = False 

def parse_http_request(request):
    """
    Parses the HTTP request and returns a dictionary with the necessary values

    Args:
        request: bytes

    Returns:
        Dictionary with the necessary values (method, url, http_version, headers)

    Raises:
        ValueErrors if necessary
    """
    try:
        request_str = request.decode('utf-8')

        lines = request_str.split("\r\n")
        
        request_line = lines[0]
        parts = request_line.split()

        # if it is a poorly malformed request
        if len(parts) != 3:
            raise ValueError("400 Bad Request")

        method, url, http_version = parts

        # if it is an invalid http method
        if method.upper() not in http_methods:
            raise ValueError("400 Bad Request")
        
        # if it is valid http method, but not a GET
        if method.upper() != "GET":
            raise ValueError("501 Not Implemented")
        
        # Checks if its a properly formatte URL
        url_pattern = r"^http://[a-zA-Z0-9.-]+(:[0-9]+)?/.*$"
        if not re.match(url_pattern, url):
            raise ValueError("400 Bad Request")
        
        if http_version != "HTTP/1.0" or not http_version:
            raise ValueError("400 Bad Request")
        
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
                raise ValueError("400 Bad Request")
        
        return {
            "method": method,
            "url": url,
            "http_version": http_version,
            "headers": headers if headers else {}
        }
    except ValueError as e:
        raise e

def parse_url(url):
    """
    Parses the URL from the HTTP request and returns a dictionary with the necessary values

    Args:
        url: string

    Returns:
        Dictionary with the necessary values (hostname, port, path)
    """
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

def handle_path(path, config):
    """
    Handles the path of the URL

    Args:
        path: string
        config: ProxyConfig

    Returns:
        is_changed: bool
            if a special absolute path is found, isChanged is marked True, otherwise it stays False
    """
    is_changed= False
    if "/proxy/cache/enable" in path:
        config.caching_on = True
        is_changed = True
    elif "/proxy/cache/disable" in path:
        config.caching_on = False
        is_changed = True
    elif "/proxy/cache/flush" in path:
        config.cache = {}
        is_changed = True
    elif "/proxy/blocklist/enable" in path:
        config.blocklist_on = True
        is_changed = True
    elif "/proxy/blocklist/disable" in path:
        config.blocklist_on = False
        is_changed = True
    elif "/proxy/blocklist/add/" in path:
        item = path.split("/proxy/blocklist/add/")[-1]
        config.blocklist.add(item)
        is_changed = True
    elif "/proxy/blocklist/remove/" in path:
        item = path.split("/proxy/blocklist/remove/")[-1]
        config.blocklist.discard(item)
        is_changed = True
    elif "/proxy/blocklist/flush" in path:
        config.blocklist = {}
        is_changed = True
    return is_changed

def handle_server(server_request, server_socket, parsed_request):
    """
    Handles the connection to the server.
    Sends the request and then parses the server
    response (result) to send to the client.

    Args:
        server_request: string
        server_socket: scoket
        parsed_request: dict

    Returns:
        Dictionary with the necessary values (result, header, status_code)
    """
    # Build server request
    if parsed_request["headers"]:
        for header, value in parsed_request["headers"].items():
            header_str = header.decode('utf-8')
            value_str = value.decode('utf-8')
            if header_str.lower() != "connection":
                server_request += f"{header_str}: {value_str}\r\n"
    server_request += "\r\n"

    print("server request: " + server_request)
    server_socket.sendall(server_request.encode())

    result = b""
    # Receive and forward the server response
    while True:
        server_response = server_socket.recv(4096)
        result += server_response
        if not server_response:
            break

    # Parse headers from server response
    header_end = result.find(b"\r\n\r\n")
    header_str = result[:header_end].decode('utf-8', errors='ignore')
    headers = {}
    status_code = None

    # Get status line
    lines = header_str.split("\r\n")
    if len(lines) > 0:
        status_line = lines[0]
        parts = status_line.split(" ")
        if len(parts) >= 3 and parts[0].startswith("HTTP"):
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None

    # Parse headers
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    server_socket.close()
    return result, headers, status_code

def handle_client(client_conn, client_addr, config):
    """
    Handles a single client.

    Args:
        client_conn: socket
        client_addr: tuple
    """
    try:
        print(f"Connection received from {client_addr}")

        client_request = b""
        while True:
            client_request += client_conn.recv(2048)
            if b"\r\n\r\n" in client_request:
                break

        parsed_request = parse_http_request(client_request)
        url = parsed_request["url"]
        url_data = parse_url(url)

        is_changed = handle_path(url_data["path"], config)

        if is_changed:
            client_conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            client_conn.close()
            return

        if config.blocklist_on and url_data["hostname"] in config.blocklist:
            client_conn.sendall(b"HTTP/1.0 403 Forbidden\r\n\r\n")
            return

        server_socket = socket(AF_INET, SOCK_STREAM)
        proxy_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_socket.connect((url_data["hostname"], url_data["port"]))

        server_request = f"{parsed_request['method']} {url_data['path']} {parsed_request['http_version']}\r\n" \
                         f"Host: {url_data['hostname']}\r\n" \
                         f"Connection: close\r\n"

        # Add If-Modified-Since if caching is enabled and cache entry exists
        if config.caching_on and url in config.cache:
            last_modified = config.cache[url].get("last_modified")
            if last_modified:
                server_request += f"If-Modified-Since: {last_modified}\r\n"

        # Add headers from client request
        if parsed_request["headers"]:
            for header, value in parsed_request["headers"].items():
                header_str = header.decode('utf-8')
                value_str = value.decode('utf-8')
                if header_str.lower() != "connection":
                    server_request += f"{header_str}: {value_str}\r\n"
        server_request += "\r\n"

        response, headers, status_code = handle_server(server_request, server_socket, parsed_request)

        # Handle caching of the response
        if config.caching_on:
            if status_code == 304:
                client_conn.sendall(config.cache[url]["data"])
                return
            else:
                last_modified = headers.get("last-modified") or headers.get("date")
                if last_modified:
                    config.cache[url] = {
                        "data": response,
                        "last_modified": last_modified
                    }

        client_conn.sendall(response)

    except ValueError as e:
        error_message = f"HTTP/1.0 {str(e)}\r\n\r\n"
        client_conn.sendall(error_message.encode())
    finally:
        client_conn.close()

# Start of program execution
# Parse out the command line server address and port number to listen to
config = ProxyConfig()
parser = OptionParser()
parser.add_option("-p", type="int", dest="serverPort")
parser.add_option("-a", type="string", dest="serverAddress")
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = "localhost"
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

proxy_port = port
proxy_socket = socket(AF_INET, SOCK_STREAM)
proxy_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
proxy_socket.bind((address, port))
proxy_socket.listen()
print(f"Socket is listening on {address}:{port}")

while True:
    client_conn, client_addr = proxy_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_conn, client_addr, config))
    client_thread.start()