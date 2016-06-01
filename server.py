# To run this in terminal: python server.py 50000 "certs/minissl-server.pem" "certs/minissl-server.key.pem" "ClientAuth/SimpleAuth" "payload.txt"

from Crypto.Cipher import PKCS1_OAEP
import pickle
from Crypto.Cipher import AES
from socket import *
import threading
import ast
from binascii import hexlify,unhexlify
import sys
from base64 import b64decode
import keyutils
import time
import struct
import Padding

# 0: Message type
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
AUTHMETHOD = sys.argv[4]
PAYLOAD = sys.argv[5]

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
            print "Bad Certificate!"
            return 0
        else:
            return 1

    def smartSend(self, socket, data):
        data = struct.pack('>I', len(data)) + data
        socket.sendall(data)

    def smartRecv(self, socket):
        message_length = self.recvHelper(socket, 4)
        if not message_length:
            return None
        message_length = struct.unpack('>I', message_length)[0]
        return self.recvHelper(socket, message_length)

    def recvHelper(self, socket, message_length):
        data = ''
        while len(data) < message_length:
            packet = socket.recv(message_length - len(data))
            if not packet:
                return None
            data += packet
        return data

    def readCertificate(self, file_path):
        f = open(file_path)
        cert = f.read()
        f.close()
        return cert

    @staticmethod
    def init_connection(self, message_tuple):
        all_sent_msgs = ""
        all_recv_msgs = ""

        cert = self.readCertificate(SERVERCERT)
        clientNonce = message_tuple[1]
        initNonce = keyutils.generate_nonce(28)

        if AUTHMETHOD == 'ClientAuth':
            reqClientCert = "CertReq"
        else :
            reqClientCert = ""

        print "Initiating handshake..."
        initMsg = ("ServerInit", initNonce, message_tuple[2], cert, reqClientCert,)
        initMsg = pickle.dumps(initMsg)
        all_sent_msgs += initMsg
        self.smartSend(self.client_sock, initMsg)

        data = self.smartRecv(self.client_sock)
        all_recv_msgs += data
        initResponse = pickle.loads(data)

        # VALIDATING CERTIFICATE #
        if reqClientCert:
            if not self.validate_certificate(initResponse[RECV_CERT]):
                print "Bad Certificate!"
                return

        # DERIVING PUBLIC KEY FROM CERTIFICATE + PRIVATE KEY#
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

        self.smartSend(self.client_sock, finalMsg)

        print "Handshake was succesful. Waiting for command..."
        data = self.smartRecv(self.client_sock)
        command = pickle.loads(data)

        if (command[0] == "GET"):
            # FINAL STEP #
            print "Received GET command. Sending file..."
            file = open(PAYLOAD, 'r')
            file_data = file.read()
            init_vector = keyutils.generate_random(16)
            aes_cipher = AES.new(session_key_one, AES.MODE_CFB, init_vector)
            file_data = Padding.appendPadding(file_data)
            encrypted_data = aes_cipher.encrypt(file_data)
            pickle_payload = (init_vector, encrypted_data)
            pickle_payload = pickle.dumps(pickle_payload)
            self.smartSend(self.client_sock, pickle_payload)
            print "File sent to client."


    def run(self):
        print "Connected to:"
        print(address)
        while 1:
            message = self.smartRecv(self.client_sock)
            if not message:
                break

            message_tuple = pickle.loads(message)

            if (message_tuple[0] == "ClientInit"):
                try:
                    self.init_connection(self, message_tuple)
                except Exception, e:
                    print "Transfer failed with error: " + e
                else:
                    print "Transfer was succesful."
                finally:
                    self.client_sock.close()
                    print "Session terminated."
                    break

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
server_socket.bind(('', int(LISTEN_PORT)))
server_socket.listen(5)

while 1:
     (client_socket, address) = server_socket.accept()
     Client(server_socket, client_socket, address)
