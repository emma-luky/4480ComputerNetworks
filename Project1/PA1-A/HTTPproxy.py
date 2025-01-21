# Place your imports here
import signal
from optparse import OptionParser
import sys
from socket import *

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

# TODO: Put function definitions here
def parse_http_request(request_line: str):
    try:
        # Split the request line into components
        method, url, http_version = request_line.split()

        if method.upper() == 'GET':
            return {
                "method": method,
                "url": url,
                "http_version": http_version
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

    # Handle optional port in URL
    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    else:
        port = 80  # Default HTTP port

    return hostname, port, path

# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100


# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# TODO: Set up sockets to receive requests
# IMPORTANT!
# Immediately after you create your proxy's listening socket add
# the following code (where "skt" is the name of the socket here):
# skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Without this code the autograder may cause some tests to fail
# spuriously.
proxyPort = port
proxySocket = socket(AF_INET, SOCK_DGRAM)
proxySocket.bind((address, port))
proxySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print(f"Socket is listening on {address}:{port}")

clientSocket = socket(AF_INET, SOCK_DGRAM)
message = input('Input HTTP Request:')
clientSocket.sendto(message.encode(), (address, port))
modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
print(parse_http_request(modifiedMessage))
clientSocket.close()

serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', port))
serverSocket.bind(('', serverPort))
print('The server is ready to receive')


# TODO: accept and handle connections
while True:
    message, clientAddress = serverSocket.recvfrom(2048)
    modifiedMessage = message.decode().upper()
    # TODO: instead of client address, proxy?
    serverSocket.sendto(modifiedMessage.encode(), 
    clientAddress)
    # serverSocket.sendto(modifiedMessage.encode(), 
    # (address, port))