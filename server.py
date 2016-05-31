# > Wait for initialisation message
# > Generate Nonce and send certificate
# > Potential for certificate request from the client
from Crypto.Cipher import PKCS1_OAEP
import pickle
from Crypto.Cipher import AES
import socket
import threading
import ast
from base64 import b64decode
import keyutils

RECV_CERT = 5

class Client(threading.Thread):
    def __init__(self, server_socket, client_socket, address):
        # type: (socket, address) -> client
        threading.Thread.__init__(self)
        self.server_sock = server_socket
        self.client_sock = client_socket
        self.addr = address
        self.start()

# THIS HELPER VALIDATES CERTIFICATE #

    def validate_certificate(self,recv_certificate):
        print recv_certificate
        if not keyutils.verify_certificate(self.readCertificate("certs/minissl-ca.pem"), recv_certificate):
            print "Bad Certificate"
            return 0
        else:
            return 1


    def readCertificate(self, file_path):
	f = open(file_path)
	cert = f.read()
        f.close()
	return cert

    @staticmethod
    def init_connection(self, message_tuple):
        cert = self.readCertificate("certs/minissl-server.pem")
        clientNonce = message_tuple[1]
        initNonce = keyutils.generate_nonce(28)
        reqClientCert = raw_input("Would You Like A Client's Certificate? (Y/N): ")

        if reqClientCert == 'Y':
            reqClientCert = "CertReq"
        else :
            reqClientCert = ""

        initMsg = ("ServerInit:", initNonce, message_tuple[2], cert, reqClientCert)
        initMsg = pickle.dumps(initMsg)
        self.client_sock.send(initMsg)

		#TODO Open certificate file, read in and send to client.
		#     Verify return certificate.

        data = self.client_sock.recv(5000)
        initResponse = pickle.loads(data)
        print initResponse[RECV_CERT]
        if not self.validate_certificate(initResponse[RECV_CERT]):
            print "Bad Cert"
            return

        # DERIVING PUBLIC KEY FROM CERTIFICATE + PRIVATE KEY#
        public_key = keyutils.read_pubkey_from_pem(self.readCertificate("certs/minissl-server.pem"))
        private_key = keyutils.read_privkey_from_pem(self.readCertificate("certs/minissl-server.key.pem"))

                # COMPUTING SECRET #
        secret = keyutils.generate_random(46)

        # DERIVING KEYS FROM SECRET #

        session_key_one = keyutils.create_hmac(secret, clientNonce + initNonce + '00000000')
        session_key_two = keyutils.create_hmac(secret, clientNonce + initNonce + '11111111')


        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(initResponse[3])
        aes_cipher = AES.new(aes_key, AES.MODE_CFB, initResponse[2])
        print aes_cipher.decrypt(initResponse[1])





    def run(self):
        print(address)
        while 1:
            message = self.client_sock.recv(1024)
            if not message:
                break
            print message
            message_tuple = pickle.loads(message)

            if (message_tuple[0] == "ClientInit"):
                self.init_connection(self, message_tuple)
                # Split message into parts and send to handler.


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', 50000))
server_socket.listen(5)

while 1:
    (client_socket, address) = server_socket.accept()
    Client(server_socket, client_socket, address)
