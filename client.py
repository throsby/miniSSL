import keyutils
import socket
import threading


# > Split command line argument
# > Select encryption and hashing based on input


def initialise(socket):
    initNonce = keyutils.generate_nonce(28)
    initMsg = "ClientInit:" + initNonce + ":AES-HMAC"
    socket.send(initNonce)  # Sending the first message.



SERVER = "192.168.0.1"
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(SERVER)


initialise(socket)


