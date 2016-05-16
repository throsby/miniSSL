# > Wait for initialisation message
# > Generate Nonce and send certificate
# > Potential for certificate request from the client

import socket
import threading

import keyutils


class Client(threading.Thread):
    def __init__(self, socket, address):
        # type: (socket, address) -> client
        threading.Thread.__init__(self)
        self.sock = socket
        self.addr = address
        self.start()

    def run(self):
        while 1:
            print('Client Sent: ', self.sock.recv(1024).decode())
            initNonce = keyutils.generate_nonce(28)


serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(socket.gethostname(), 80)
serverSocket.listen(5)

while 1:
    (clientSocket, address) = serverSocket.accept()
    Client(socket, address)
