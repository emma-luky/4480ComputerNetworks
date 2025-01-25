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

# Parse the HTTP Request
def parse_http_request(request: bytes):  
    """Parses the HTTP request and returns a dictionary with the necessary values"""
    """Raises ValueErrors if necessary"""
    try:
        request_str = request.decode('utf-8')

        lines = request_str.split("\r\n")
        
        request_line = lines[0]
        parts = request_line.split()

        if len(parts) != 3:
            raise ValueError("400 Bad Request")

        method, url, http_version = parts
        # method, url, http_version = request_line.split()

        if method.upper() not in http_methods:
            raise ValueError("400 Bad Request")
        if method.upper() != "GET":
            raise ValueError("501 Not Implemented")
        
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

# Parse the URL
def parse_url(url):
    """Parses the URL from the HTTP request and returns a dictionary with the necessary values"""
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

def handle_client(clientConn, clientAddr):
    """Handles a single client"""
    try:
        print(f"Connection received from {clientAddr}")
        clientRequest = clientConn.recv(2048)

        parsed_request = parse_http_request(clientRequest)
        url_data = parse_url(parsed_request["url"])

        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.connect((url_data["hostname"], url_data["port"]))

        # Build server request
        server_request = f"{parsed_request['method']} {url_data['path']} {parsed_request['http_version']}\r\n" \
                         f"Host: {url_data['hostname']}\r\n" \
                         f"Connection: close\r\n"
        if parsed_request["headers"]:
            for header, value in parsed_request["headers"].items():
                header_str = header.decode('utf-8')
                value_str = value.decode('utf-8')
                if header_str.lower() != "connection":
                    server_request += f"{header_str}: {value_str}\r\n"
        server_request += "\r\n"

        print("server request: " + server_request)
        serverSocket.sendall(server_request.encode())

        # Receive and forward the server response
        while True:
            server_response = serverSocket.recv(4096)
            if not server_response:
                break
            clientConn.sendall(server_response)

        serverSocket.close()
    except ValueError as e:
        error_message = f"HTTP/1.0 {str(e)}\r\n\r\n"
        clientConn.sendall(error_message.encode())
    finally:
        clientConn.close()

# Start of program execution
# Parse out the command line server address and port number to listen to
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

proxyPort = port
proxySocket = socket(AF_INET, SOCK_STREAM)
proxySocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
proxySocket.bind((address, port))
proxySocket.listen()
print(f"Socket is listening on {address}:{port}")

while True:
    clientConn, clientAddr = proxySocket.accept()
    print(f"Connection received from {clientAddr}")
    client_thread = threading.Thread(target=handle_client, args=(clientConn, clientAddr))
    client_thread.start()