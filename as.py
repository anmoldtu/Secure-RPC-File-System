import base64
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime; 
import socket
import os
AU_HOST = '127.0.0.1'
AU_PORT = 3500
TGS_HOST = '127.0.0.1'
TGS_PORT = 3600
PATH = os.getcwd()
SALT = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'
SALT_TGS = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'

# Create key using Salt and Password
def create_key(password,SALT):
    key = PBKDF2(password, SALT, dkLen=32)
    return key
# encoding message in utf-8
def en(message):
    try:
        message = message.encode('utf-8')
    except (UnicodeEncodeError, AttributeError) as e:
        print(e)
    return message

# de-encoding message from utf-8 after encoding it with base-64 encoding
# used with Encryption function
def dn(message):
    # print("Inside DN \n")
    try:
        # print(type(message))
        # print(message)
        message = b64encode(message).decode('utf-8')
        # print(message)
        return message
    except (UnicodeDecodeError, AttributeError,TypeError) as e:
        print(e)
        return message

# de-encoding message from utf-8
# used with sockets
def dne(message):
    # print("Inside DNE \n")
    try:
        # print(type(message))
        # print(message)
        message = message.decode('utf-8')
        # print(message)
        return message
    except (UnicodeDecodeError, AttributeError,TypeError) as e:
        print(e)
        return message
# creating dictionary from string
def string_json(message):
    try:
        data = json.loads(message)
    except (ValueError,TypeError):
        data = message
    return data
# creating string from dictionary
def json_string(message):
    try:
        # print(message)
        # print(type(message))
        data = json.dumps(message)
        # print('z')
        # print(type(data))
    except (ValueError,TypeError) as e:
        data = message
        # print(e)
    return data
# searching for credentials of client
def find_credentials(user_id):
    for root, dir, files in os.walk(PATH):
      if user_id in files:
          file = open(user_id, 'r') 
          line = file.readline()
          password = line.strip()
          line = file.readline()
          host = line.strip()
          line = file.readline()
          port = line.strip()
          key = create_key(password,SALT)
          return key,host,port
    return None,None,None

# encrypt tgs session key using client secret key
def encrypt(key,data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(en(data))
    nonce = cipher.nonce
    data_json = {'key':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    return data_bytes

# encrypt tgt (message b) using TGS secret key
def encrypt_tgs(data,key):
    cipher = AES.new(en(key), AES.MODE_EAX)
    data = json_string(data)
    ciphertext, tag = cipher.encrypt_and_digest(en(data))
    nonce = cipher.nonce
    data_json = {'data':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    return data_bytes

def authenticate_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((AU_HOST, AU_PORT))
    while 1 :
        data, server = sock.recvfrom(4096)
        user_id = dne(data)
        key,host,port = find_credentials(user_id+'.txt')
        # creating TGS session key
        session_key = get_random_bytes(32)
        # encrypting TGS session key
        message_a = encrypt(key,session_key)
        ct = datetime.datetime.now() 
        ts = ct.timestamp() + 5000
        # creating tgt
        message_json = {'validity_period':ts,'client_id':dn(user_id),'host':dn(host),'port':dn(port),'key':dn(session_key)}
        message = json_string(message_json)
        # creating tgs secret key
        tgs_key = create_key("tgs@123",SALT_TGS)
        # encrypting TGT
        message_b = encrypt_tgs(message,tgs_key)
        
        sock.sendto(message_a, (host, int(port)))
        sock.sendto(en(message_b), (host, int(port)))


authenticate_client()

    

    



