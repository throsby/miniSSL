# To run this in terminal: python client.py "127.0.0.1" 50000 "certs/minissl-client.pem" "certs/minissl-client.key.pem"

# TODO:
# > CHECK FOR EXPIRY OF CERTIFICATE
# > GENERATE RSA KEY AND BEGIN ENCRYPTION
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import socket
import threading
import binascii
import ast
import keyutils
import pickle
import sys

# DEFINES

RECV_HEAD = 0
RECV_NONCE = 1
RECV_CERT = 3
CERT_REQ  = 4

message_size = 4096

path_to_ca_cert = "certs/minissl-ca.pem"

# Run arguments
DESTINATION_IP = sys.argv[1]
DESTINATION_PORT = sys.argv[2]
CLIENT_CERT = sys.argv[3]
CLIENT_PRIVATEKEY = sys.argv[4]

###################

def verifyHash(key, all_msgs, recv_hash):
    hashed_msgs = keyutils.create_hmac(key, all_msgs)
    if hashed_msgs == recv_hash:
        return 1
    return 0


# THIS HELPER VALIDATES CERTIFICATE #

def validate_certificate(recv_certificate):
    if not keyutils.verify_certificate(readCertificate(path_to_ca_cert), recv_certificate):
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
    all_recv_msgs = ""
    all_sent_msgs = ""
    initNonce = keyutils.generate_nonce(28)
    initMsg = ("ClientInit", initNonce, "AES-HMAC")
    initMsg = pickle.dumps(initMsg)
    all_sent_msgs += initMsg
    socket.send(initMsg)  # Sending the first message.
    data = socket.recv(message_size)
    initResponse = pickle.loads(data)
    all_recv_msgs += data
    # VALIDATING CERTIFICATE (See helper function above) #
    if not validate_certificate(initResponse[RECV_CERT]):
        print "Bad Cert"
        return

    # DERIVING PUBLIC KEY FROM CERTIFICATE + PRIVATE KEY#
    public_key = keyutils.read_pubkey_from_pem(initResponse[RECV_CERT])
    private_key = keyutils.read_privkey_from_pem(readCertificate(CLIENT_PRIVATEKEY))

    # COMPUTING SECRET #
    secret = keyutils.generate_random(46)

    # DERIVING KEYS FROM SECRET #

    session_key_one = keyutils.create_hmac(secret, initResponse[RECV_NONCE] + initNonce + '00000000')
    session_key_two = keyutils.create_hmac(secret, initResponse[RECV_NONCE] + initNonce + '11111111')

    msgHMAC = keyutils.create_hmac(session_key_two, all_recv_msgs)
    # TODO: NEED TO DECRYPT THE AES KEY FIRST AND THEN DECRYPT THE MESSAGE WITH THAT KY
    encrypted = keyutils.encrypt_with_rsa_hybrid(secret, public_key)

    confirm_msg = ("ClientKex:", encrypted[0], encrypted[1], encrypted[2], msgHMAC,)

    # IF CERTIFICATE REQUIRED THEN SEND IT
    if len(initResponse) == 5:
        if initResponse[CERT_REQ] == "CertReq":
            signedNonse = private_key.sign(initResponse[RECV_NONCE], private_key)
            confirm_msg = confirm_msg + (readCertificate("certs/minissl-client.pem"), str(signedNonse[0]), )

    p = pickle.dumps(confirm_msg)
    all_sent_msgs += p
    socket.send(p)
    finalMsg = socket.recv(message_size)

    if not verifyHash(session_key_two, all_recv_msgs, finalMsg):
        print "BAD HASH"
        return

    print "Sending get command"
    get_message = ("GET",)
    pickle_message = pickle.dumps(get_message)
    socket.send(pickle_message)

    file_data_pickle = socket.recv(message_size)
    file_date = pickle.loads(file_data_pickle)
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(file_date[2])
    aes_cipher = AES.new(aes_key, AES.MODE_CFB, file_date[1])
    file_data = aes_cipher.decrypt(file_date[0])

    f = open("received_payload.txt", 'wb')
    f.write(file_data)
    f.close()
    print "File received"
    #socket.close()
    print "Client terminated"
    sys.exit()


SERVER_IP = DESTINATION_IP
print(SERVER_IP)
raw_input('Enter To Continue: ')
receiveSem = threading.Semaphore([1])
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((SERVER_IP, int(DESTINATION_PORT)))


initialise(socket)
