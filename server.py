from datetime import time
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime
import sys
import os
import socket
from shutil import copyfile
from socket import SHUT_RDWR
import socket
import os
AU_HOST = ''
AU_PORT = 3500
TGS_HOST = ''
TGS_PORT = 3600
HOST = ''
PORT = 3700
PASSWORD = 'service@'
PATH = os.getcwd()
SALT = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'
SALT_TGS = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'
SALT_SERVICE = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'
# Create key using Salt and Password
def create_key(password,SALT=SALT_SERVICE):
    key = PBKDF2(password, SALT, dkLen=32)
    return key
# encoding message in utf-8
def en(message):
    try:
        message = message.encode('utf-8')
        return message
    except (UnicodeEncodeError, AttributeError):
        return message
# de-encoding message from utf-8 after encoding it with base-64 encoding
# used with Encryption function
def dn(message):
    try:
        message = b64encode(message).decode('utf-8')
        return message
    except (UnicodeDecodeError, AttributeError,TypeError) as e:
        return message
# de-encoding message from utf-8
# used with sockets
def dne(message):
    try:
        message = message.decode('utf-8')
        return message
    except (UnicodeDecodeError, AttributeError) as e:
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
        data = json.dumps(message)
    except (ValueError,TypeError):
        data = message
    return data

# decrypt client information using server secret key
def decrypt_message(message,key): 
    message = string_json(message)
    
    nonce = message['nonce']
    tag = message['tag']
    data = message['cipher']
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(en(nonce)))
        message = cipher.decrypt_and_verify(b64decode(en(data)),b64decode(en(tag)))
        message = dne(message)
        message = string_json(message)
        return message['client'], message['host'], message['port'],message['validity'],message['key']
    except (ValueError, KeyError):
        pass

# decrypt authenticator using session key
def decrypt_authenticator(message,key):
    message = string_json(message)
    nonce = message['nonce']
    tag = message['tag']
    data = message['cipher']
    try:
        cipher = AES.new(b64decode(en(key)), AES.MODE_EAX, nonce=b64decode(en(nonce)))
        message = cipher.decrypt_and_verify(b64decode(en(data)),b64decode(en(tag)))
        
        message = dne(message)
        
        message = string_json(message)
        
        return message['client_id'], message['timestamp']
    except (ValueError, KeyError):
        pass
        return None,None

# encrypt rpc using session key
def encrypt_rpc(message,key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(en(message))
    nonce = cipher.nonce
    rpc = {'rpc':dn(ciphertext), 'tag':dn(tag), 'nonce':dn(nonce)}
    rpc = json_string(rpc)
    rpc = en(rpc)
    return rpc

# decrypt rpc using session key
def decrypt_rpc(message, key):
    message = string_json(message)
    rpc = en(message['rpc'])
    nonce = en(message['nonce'])
    tag = en(message['tag'])
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(nonce))
        data = cipher.decrypt_and_verify(b64decode(rpc),b64decode(tag))
        print('Dec\n')
        print(data)
        print(dne(data))
        data = dne(data)
        print(data)
        return data
    except (ValueError, KeyError):
        print("Incorrect decryption")

def encrypt_auth(timestamp,session_key):
    cipher = AES.new(b64decode(en(session_key)), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(en(str(timestamp)))
    nonce = cipher.nonce
    data_json = {'cipher':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    print(data_bytes)
    return data_bytes

def grant_access(password):
    print('IN GA\n\n')
    print(PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    while 1 :
        message_e, addr = sock.recvfrom(4096)
        message_f, addr = sock.recvfrom(4096)
        key = create_key(password)
        print(key)
        print(message_e)
        print(message_f)
        print(dne(message_e))
        client_d,host,port,ts,session_key = decrypt_message(dne(message_e),key)
        client_id, timestamp = decrypt_authenticator(dne(message_f),session_key)
        if client_d==client_id:
            message_h = encrypt_auth(timestamp,session_key)
            sock.sendto(en(message_h),(host,int(port)))
            sock.close()
            print('Out GA\n\n')
            return b64decode(en(session_key))
        sock.close()
        return None
        
# def make_call(ss_key):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((HOST, PORT))
#     while 1:
#         message, addr = sock.recvfrom(4096)
#         print('Finall \n')
#         message = dne(message)
#         print(message)
#         message = decrypt_rpc(message,ss_key)
#         print(message)
#         data = encrypt_rpc('done',ss_key)
#         print(data)
#         sock.sendto(data,addr)

# ss_key = grant_access('service@')
# make_call(ss_key)

# File_Server for Distributed SRPC File System
import sys
import os
import socket
from shutil import copyfile
from socket import SHUT_RDWR


copyCount = {}

def initCopyCount():
    files = sorted(os.listdir())
    for textFile in files:
        copyCount[textFile] = 1


FS_Ports = {9000: "F1", 9001: "F2"}

myPort = 9000

Client_PORT = 7000



# def recieve_SRPC(s, PORT):

#     request = {"cmd" : None, "data": None}


#     # block beyond 1 connection
#     s.listen(5)

#     # enter blocking mode
#     c, addr = s.accept()

#     print("Connected to - ", addr)

#     # receive and decode
#     x = c.recv(1024).decode('utf-8')


#     # extract data
#     message = x.split()

#     request["cmd"] = Commands[message[0]]
#     request["data"] = message[1]

#     # Close the connection with the client
#     c.close()

#     # decryption

#     # cmd = input("Enter Command: ")
#     # data = input("Enter Data: ")
#     # request["cmd"] = cmd
#     # request["data"] = data

#     return request

def send_SRPC_response(s, data,key):
    # logic to send back data to client
    # encrypt
    # send
    # print(s.connect(('', Client_PORT)))

    send_data = encrypt_rpc(data,key)

    s.send(send_data)

    # print(data)
    return

# present working directory
def pwd(*args):
    data = os.getcwd().split("/")[-1]
    return data

# list elements
def ls(*args):
    ls_list = sorted(os.listdir())
    data = ""
    for x in ls_list:
        data = data + x + "\t"
    return data

# copy File
def cp(file_names):

    file_name = file_names[0]
    output_file_name = file_names[1]

    # copyCount[file_name] = copyCount[file_name] + 1
    # output_file_name = file_name.split('.')[0] + "_" + str(copyCount[file_name]) + ".txt"
    # copyCount[output_file_name] = 1
    try:
        copyfile(file_name, output_file_name)
        data = "Copy success: " + output_file_name + " created."
    except Exception as err:
        data = str(err)

    return data

# display File
def cat(file_name):
    # data = {}
    try:
        f = open(file_name[0], 'r')
        data = f.read()
        f.close()
    except Exception as err:
        data = str(err)
    return data

def createSocket():
    return

Commands = {"pwd": pwd, "ls": ls, "cp": cp, "cat": cat}

def main():
    global PORT
    PORT = int(sys.argv[1])
    os.chdir(FS_Ports[PORT])
    initCopyCount()
    key = grant_access(PASSWORD)
    print('DONONONOi\n')


    print("My Port: ",PORT)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Socket ok!")
    except socket.error as err:
        print ("socket creation failed -- Exiting")
        s.close()
        exit(0)

    try:
        s.bind(('', PORT))
        print("Bind Ok!")
    except socket.error as err:
        print ("%s\nSocket binding failed -- Exiting" %err)
        s.close()
        exit(0)

    request = {"cmd" : None, "data": None}

    s.listen(1)
    print("Listening..")

    c, addr = s.accept()
    print("Connected to", addr)

    while(True):
        try:
            # enter blocking mode
            # block beyond 1 connection

            # receive and decode
            x = c.recv(1024)
            x = decrypt_rpc(dne(x),key)


            # extract data
            message = x.split()

            print("Received RPC: ", message[0])

            request["cmd"] = message[0]
            request["data"] = message[1:]

            if message[0] == "esc" :

                data = 'disconnected'
                print("Sending Response to RPC: ", data)
                send_SRPC_response(c, data,key)

                print("RPC Response Sent")

                c.close()
                s.close()
                print("Socket Closed")
                key = grant_access(PASSWORD)
                print('DONONONO\n')



                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    print("Socket ok!")
                except socket.error as err:
                    print ("socket creation failed -- Exiting")
                    s.close()
                    exit(0)

                try:
                    s.bind(('', PORT))
                    print("Bind Ok!")
                except socket.error as err:
                    print ("%s\nSocket binding failed -- Exiting" %err)
                    s.close()
                    exit(0)

                s.listen(1)
                print("Listening again..")

                c, addr = s.accept()
                print("Connected to", addr)
                continue

            data = Commands[request["cmd"]](request["data"])

            print("Sending Response to RPC: ", data)

            send_SRPC_response(c, data,key)

            # Close the connection with the client
            # c.close()

        except Exception as e:

            print("ERROR: ", sys.exc_info()[0],"\n" ,e)
            c.close()
            s.close()
            exit(0)

    c.close()
    s.close()

if __name__ == "__main__":
    main()

