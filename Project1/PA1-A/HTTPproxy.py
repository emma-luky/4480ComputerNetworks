# Place your imports here
import signal
from optparse import OptionParser
import sys
from socket import *

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

# TODO: Put function definitions here
def parse_http_request(request: str):
    try:
        method, url, http_version = request.split()

        if method.upper() == "GET":
            # # TODO: Parse headers
            # headers = {}
            # for line in lines[1:]:
            #     if not line.strip():  # Stop at the first empty line (end of headers)
            #         break
            #     if ": " in line:
            #         header_name, header_value = line.split(": ", 1)
            #         headers[header_name] = header_value
            #     else:
            #         raise ValueError("400 Bad Request: Malformed header.")
            return {
                "method": method,
                "url": url,
                "http_version": http_version,
                # "headers": headers
            }
        else: 
            raise ValueError("501 Not Implemented")    
    except ValueError:
        raise ValueError("400 Bad Request")


# Parse the URL into hostname, port, and path
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
        print("http: " + parsed_request["http_version"])
        print("method: " + parsed_request["method"])
        print("url: " + parsed_request["url"])
        # print("headers: " + parsed_request["headers"])
        url_data = parse_url(parsed_request["url"])

        serverSocket = socket(AF_INET, SOCK_STREAM)
        serverSocket.connect((url_data["hostname"], url_data["port"]))

        server_request = f"{parsed_request["method"]} {parsed_request["http_version"]}\r\n \
            Host: {url_data["path"]} \r\n \
            Connection: close"
        
        # TODO: add headers if they exists
        serverSocket.sendall(server_request.encode())

        server_response = serverSocket.recv(url_data["port"])
        print("Response from server received.")

        clientConn.sendall(server_response)

    except Exception as e:
        print("Error:", e)
        clientConn.sendall(b"HTTP/1.0 500 Internal Server Error\r\n\r\n")

    clientConn.close()