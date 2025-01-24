# Place your imports here
import signal
from optparse import OptionParser
import sys
from socket import *

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)


# Parse the HTTP Request
def parse_http_request(request: str):  
    try:
        # Split the request into lines
        lines = request.split("\r\n")
        
        # Parse the request line
        request_line = lines[0]
        method, url, http_version = request_line.split()
        
        if method.upper() != "GET":
            raise ValueError("501 Not Implemented")
        
        # Parse headers
        headers = []
        for line in lines[1:]:
            if not line.strip():
                break
            if ": " in line:
                headers.append(line)
            else:
                raise ValueError("400 Bad Request")
        
        return {
            "method": method,
            "url": url,
            "http_version": http_version,
            "headers": headers if headers else None
        }
    except ValueError:
        raise ValueError("400 Bad Request")
    

# Parse the URL
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

    clientRequest = clientConn.recv(2048).decode()

    try:
        parsed_request = parse_http_request(clientRequest)
        url_data = parse_url(parsed_request["url"])

        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.connect((url_data["hostname"], url_data["port"]))
        server_request = f"{parsed_request['method']} {url_data['path']} {parsed_request['http_version']}\r\n \
            Host: {url_data['hostname']} \r\n \
            Connection: close\r\n"
        if parsed_request["headers"]:
            for header in parsed_request["headers"]:
                server_request += header + "\r\n"
        server_request += "\r\n"
        print("server request: " + server_request)
        serverSocket.sendall(server_request.encode())

        server_response = serverSocket.recv(4096)
        print("Response from server received.")

        clientConn.sendall(server_response)

    except Exception as e:
        print("Error:", e)
        clientConn.sendall(b"HTTP/1.0 501 Not Implemented\r\n\r\n")

    clientConn.close()
    serverSocket.close()