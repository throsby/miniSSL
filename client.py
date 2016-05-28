import socket
import threading

import keyutils

# DEFINES

RECV_HEAD = 0
RECV_NONCE = 1
RECV_CERT = 2

###################

# > Split command line argument
# > Select encryption and hashing based on input

def validate_certificate(recv_certificate):
    if not keyutils.verify_certificate(readCertificate("certs/minissl-ca.pem"), recv_certificate):
        print "Bad Certificate"
        return 0
    elif keyutils.read_issuer(recv_certificate) != keyutils.read_issuer(readCertificate("certs/minissl-server.pem")):
            print "Bad Issuer"
            return 0
    else:
        return 1



def readCertificate(file_path):
    f = open(file_path)
    cert = f.read()
    f.close()
    return cert

def initialise(socket):
    initNonce = keyutils.generate_nonce(28)
    initMsg = ("ClientInit:" + str(initNonce) + ":AES-HMAC")
    socket.send(initMsg)  # Sending the first message.
    data = socket.recv(2096)
    initResponse = data.split(":")
    if validate_certificate(initResponse[RECV_CERT]):
        print "OK"


SERVER = "127.0.0.1"
print(SERVER)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER, 50000))


initialise(socket)


