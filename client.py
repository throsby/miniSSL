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

def readCertificate(file_path):
    f = open(file_path)
    cert = f.read()
    return cert

def initialise(socket):
    initNonce = keyutils.generate_nonce(28)
    initMsg = ("ClientInit:" + str(initNonce) + ":AES-HMAC")
    socket.send(initMsg)  # Sending the first message.
    data = socket.recv(2096)
    initResponse = data.split(":")
    print initResponse[RECV_CERT]
    compare_cert = readCertificate("certs/minissl-server.pem")
    if initResponse[RECV_CERT] == compare_cert :
        print "YAY"
    else:
        print "NAY"

SERVER = "127.0.0.1"
print(SERVER)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER, 50000))


initialise(socket)


