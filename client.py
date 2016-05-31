# TODO:
# > CHECK FOR EXPIRY OF CERTIFICATE
# > GENERATE RSA KEY AND BEGIN ENCRYPTION
from Crypto.Cipher import AES
import socket
import threading
import binascii
import ast
import keyutils

# DEFINES

RECV_HEAD = 0
RECV_NONCE = 1
RECV_CERT = 3
CERT_REQ  = 4

###################




# THIS HELPER VALIDATES CERTIFICATE #

def validate_certificate(recv_certificate):
    if not keyutils.verify_certificate(readCertificate("certs/minissl-ca.pem"), recv_certificate):
        print "Bad Certificate"
        return 0
    elif keyutils.read_issuer(recv_certificate) != keyutils.read_issuer(readCertificate("certs/minissl-server.pem")):
            print "Bad Issuer"
            return 0
    else:
        return 1


# THIS HELPER READS CERTIFICATE FROM FILE #
def readCertificate(file_path):
    f = open(file_path)
    cert = f.read()
    f.close()
    return cert


# THIS HELPER INITIALISES THE CONNECTIONS #
def initialise(socket):
    initNonce = keyutils.generate_nonce(28)
    initMsg = ("ClientInit:" + str(initNonce) + ":AES-HMAC")
    socket.send(initMsg)  # Sending the first message.
    data = socket.recv(2096)
    initResponse = data.split(":")

    # VALIDATING CERTIFICATE (See helper function above) #
    if not validate_certificate(initResponse[RECV_CERT]):
        print "Bad Cert"
        return

    # DERIVING PUBLIC KEY FROM CERTIFICATE + PRIVATE KEY#
    public_key = keyutils.read_pubkey_from_pem(initResponse[RECV_CERT])
    private_key = keyutils.read_privkey_from_pem(readCertificate("certs/minissl-client.key.pem"))

    # COMPUTING SECRET #
    secret = keyutils.generate_random(46)

    # DERIVING KEYS FROM SECRET #

    session_key_one = keyutils.create_hmac(secret, initResponse[RECV_NONCE]+ initNonce + '00000000')
    session_key_two = keyutils.create_hmac(secret, initResponse[RECV_NONCE] + initNonce + '11111111')

    msgHMAC = keyutils.create_hmac(session_key_two, initMsg + data)
    # TODO: NEED TO DECRYPT THE AES KEY FIRST AND THEN DECRYPT THE MESSAGE WITH THAT KY
    print initResponse[CERT_REQ]
    encrypted = keyutils.encrypt_with_rsa_hybrid("HELLOWORLD", public_key)

    confirm_msg = "ClientKex:", encrypted[0], encrypted[1], encrypted[2], msgHMAC,

    # IF CERTIFICATE REQUIRED THEN SEND IT
    if len(initResponse) == 5:
        if initResponse[CERT_REQ] == "CertReq":
            print "ADDING CERTIFICATE"
            signedNonse = private_key.sign(initResponse[RECV_NONCE], private_key)
            confirm_msg = confirm_msg + (readCertificate("certs/minissl-client.pem"), str(signedNonse[0]), )

    p = pickle.Pickler(confirm_msg)
    socket.send(p)



SERVER = "127.0.0.1"
print(SERVER)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER, 50000))


initialise(socket)
