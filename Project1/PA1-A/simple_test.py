from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('localhost', 2100))
sock.sendall(b'GET http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n')

# sock.sendall(b'GET http://localhost:8765/proxy/cache/flush HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/proxy/cache/enable HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/ HTTP/1.0\r\n\r\n')
# sock.sendall(b'GET http://localhost:8765/ HTTP/1.0\r\n\r\n')

                #GET http://www.flux.utah.edu HTTP/1.0
# sock.sendall(b'GET http://www.google.com/ HTTP/1.0\r\nConnection: keep-alive\r\n\r\n')
# sock.sendall(b'GIBBERISH http://www.flux.utah.edu/cs4480/simple.html HTTP/1.0\r\n\r\n')

print(sock.makefile('rb').read())