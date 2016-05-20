import socket
import threading

import keyutils


# > Split command line argument
# > Select encryption and hashing based on input


def initialise(socket):
    initNonce = keyutils.generate_nonce(28)
    initMsg = ("ClientInit:" + str(initNonce) + ":AES-HMAC")
    socket.send(initMsg)  # Sending the first message.


SERVER = "127.0.0.1"
print(SERVER)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER, 50000))


initialise(socket)


