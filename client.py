# TODO:
# > CHECK FOR EXPIRY OF CERTIFICATE
# > GENERATE RSA KEY AND BEGIN ENCRYPTION

import socket
import threading

import keyutils

# DEFINES

RECV_HEAD = 0
RECV_NONCE = 1
RECV_CERT = 2
CERT_REQ  = 3

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

    # DERIVING PUBLIC KEY FROM CERTIFICATE #
    public_key = keyutils.read_pubkey_from_pem(initResponse[RECV_CERT])

    # COMPUTING SECRET #
    secret = keyutils.generate_random(46)

    # DERIVING KEYS FROM SECRET #

    session_key_one = keyutils.create_hmac(secret, "00000000")
    session_key_two = keyutils.create_hmac(secret, "11111111")

    # CHECK IF CERT REQUIRED #
    if len(initResponse) == 4:
        if initResponse[3] == "CertReq":
            msg = "ClientInit:" + initNonce + ":AES-HMAC:"
            msgHMAC = keyutils.create_hmac(session_key_two,


SERVER = "127.0.0.1"
print(SERVER)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER, 50000))


initialise(socket)


