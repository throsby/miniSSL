# > Wait for initialisation message
# > Generate Nonce and send certificate
# > Potential for certificate request from the client

import socket
import threading

import keyutils


class Client(threading.Thread):
    def __init__(self, server_socket, client_socket, address):
        # type: (socket, address) -> client
        threading.Thread.__init__(self)
        self.server_sock = server_socket
        self.client_sock = client_socket
        self.addr = address
        self.start()

    def readCertificate(self, file_path):
	f = open(file_path)
	cert = f.read()
	return cert

    @staticmethod
    def init_connection(self, message_tuple):
        print "%s" % message_tuple[0]
        print "%s" % message_tuple[1]
        print "%s" % message_tuple[2]
        cert = self.readCertificate("certs/minissl-server.pem")
        initNonce = keyutils.generate_nonce(28)
        reqClientCert = raw_input("Would You Like A Client's Certificate? (Y/N): ")

        if reqClientCert == 'Y':
            reqClientCert = ":CertReq"
        else :
            reqClientCert = ""

        initMsg = ("ServerInit:" + str(initNonce) + message_tuple[2] + ":" + cert + str(reqClientCert))
        self.client_sock.send(initMsg)

		#TODO Open certificate file, read in and send to client.
		#     Verify return certificate.





    def run(self):
        print(address)
        while 1:
            message = self.client_sock.recv(1024)
            if not message:
                break

            message_tuple = message.split(":")

            if (message_tuple[0] == "ClientInit"):
                self.init_connection(self, message_tuple)
                # Split message into parts and send to handler.


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', 50000))
server_socket.listen(5)

while 1:
    (client_socket, address) = server_socket.accept()
    Client(server_socket, client_socket, address)
