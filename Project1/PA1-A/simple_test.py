from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('localhost', 2100))

# sock.sendall(b'GET http://localhost:8765/proxy/cache/enable HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/cache/flush HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/cache/disable HTTP/1.0\r\n\r\n')

# sock.sendall(b'GET http://localhost:8765/proxy/blocklist/enable HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/blocklist/add/google HTTP/1.0\r\n\r\n')
sock.sendall(b'GET http://google.com HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/blocklist/remove/google HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://google.com HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/blocklist/disable HTTP/1.0\r\n\r\n')


print(sock.makefile('rb').read())