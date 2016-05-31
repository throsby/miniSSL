# To run this in terminal: python server.py 50000 "certs/minissl-server.pem" "certs/minissl-server.key.pem" "payload.txt"

from Crypto.Cipher import PKCS1_OAEP
import pickle
from Crypto.Cipher import AES
import socket
import threading
import ast
import sys
from base64 import b64decode
import keyutils

    # 0: ClientKex
    # 1: AES encrypted message
    # 2: IV
    # 3: Encrypted AES key
    # 4: msgHMAC
    # 5: OPTIONAL Client certificate
RECV_CERT = 5

# Run arguments
LISTEN_PORT = sys.argv[1]
SERVERCERT = sys.argv[2]
SERVERPRIVKEY = sys.argv[3]
PAYLOAD = sys.argv[4]

class Client(threading.Thread):
    def __init__(self, server_socket, client_socket, address):
        # type: (socket, address) -> client
        threading.Thread.__init__(self)
        self.server_sock = server_socket
        self.client_sock = client_socket
        self.addr = address
        self.start()

    def verifyHash(self, key, all_msgs, recv_hash):
        hashed_msgs = keyutils.create_hmac(key, all_msgs)
        if hashed_msgs == recv_hash:
            return 1
        return 0

# THIS HELPER VALIDATES CERTIFICATE #

    def validate_certificate(self,recv_certificate):
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
        all_sent_msgs  = ""
        all_recv_msgs = ""

        cert = self.readCertificate(SERVERCERT)
        clientNonce = message_tuple[1]
        initNonce = keyutils.generate_nonce(28)
        reqClientCert = raw_input("Would You Like A Client's Certificate? (Y/N): ")

        if reqClientCert == 'Y':
            reqClientCert = "CertReq"
        else :
            reqClientCert = ""

        initMsg = ("ServerInit", initNonce, message_tuple[2], cert, reqClientCert)
        initMsg = pickle.dumps(initMsg)
        all_sent_msgs += initMsg
        self.client_sock.send(initMsg)

        data = self.client_sock.recv(5000)
        all_recv_msgs += data
        initResponse = pickle.loads(data)

        # VALIDATING CERTIFICATE #
        if not self.validate_certificate(initResponse[RECV_CERT]):
            print "Bad Cert"
            return

        # DERIVING PUBLIC KEY FROM CERTIFICATE + PRIVATE KEY#
        public_key = keyutils.read_pubkey_from_pem(initResponse[RECV_CERT])
        private_key = keyutils.read_privkey_from_pem(self.readCertificate(SERVERPRIVKEY))

        # COMPUTING SECRET #
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(initResponse[3])
        aes_cipher = AES.new(aes_key, AES.MODE_CFB, initResponse[2])
        secret = aes_cipher.decrypt(initResponse[1])

        # DERIVING KEYS FROM SECRET #
        session_key_one = keyutils.create_hmac(secret, initNonce + clientNonce + '00000000')
        session_key_two = keyutils.create_hmac(secret,  initNonce + clientNonce + '11111111')

        if not self.verifyHash(session_key_two, all_sent_msgs, initResponse[RECV_CERT - 1]):
            print "BAD HASH"
            return
        finalMsg = keyutils.create_hmac(session_key_two, all_sent_msgs)
        all_sent_msgs += finalMsg

        self.client_sock.send(finalMsg)

        # FINAL STEP #
        file = open(PAYLOAD, 'r')
        file_data = file.read()
        encrypted_data = keyutils.encrypt_with_rsa_hybrid(file_data, public_key)
        pickle_payload = pickle.dumps(encrypted_data)
        self.client_sock.send(pickle_payload)
        print "File sent to client"
        print "Server terminated"


    def run(self):
        print(address)
        while 1:
            message = self.client_sock.recv(1024)
            if not message:
                break
            message_tuple = pickle.loads(message)

            if (message_tuple[0] == "ClientInit"):
                self.init_connection(self, message_tuple)
                # Split message into parts and send to handler.

print "Listen port is:" + LISTEN_PORT
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', int(LISTEN_PORT)))
server_socket.listen(5)

(client_socket, address) = server_socket.accept()
Client(server_socket, client_socket, address)
sys.exit()
