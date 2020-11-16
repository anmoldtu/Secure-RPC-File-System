import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime; 
import os
import socket
import sys
from socket import SHUT_RDWR

SALT = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'
HOST = '127.0.0.1'
PORT = 3000
AU_HOST = '127.0.0.1'
AU_PORT = 3500
TGS_HOST = '127.0.0.1'
TGS_PORT = 3600
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 3700
client = 'client'
password = 'password'

# Create key using Salt and Password
def create_key(password):
    key = PBKDF2(password, SALT, dkLen=32)
    return key

# encoding message in utf-8
def en(message):
    try:
        message = message.encode('utf-8')
        return message
    except (UnicodeEncodeError, AttributeError) as e:
        print(e)
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

# dencrypting message to retrieve TGS Session key 
def client_tgs_session(key,messages):
    if 'key' in string_json(messages[0]):
        message_a = string_json(messages[0])
        message_b = string_json(messages[1])
    else :
        message_a = string_json(messages[1])
        message_b = string_json(messages[0])
    nonce = en(message_a['nonce'])
    tag = en(message_a['tag'])
    data = en(message_a['key'])
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(nonce))
        # decrypting and verifying using tag and Secret key of Client
        tgs_session_key = cipher.decrypt_and_verify(b64decode(data),b64decode(tag))
        tgs_session_key = dn(tgs_session_key)
        message = message_b
        return tgs_session_key, message
    except (ValueError, KeyError) as e:
        pass
    return None, None

# encrypting message using TGS session key for TGS server
def encrypt_tgs_authorization (key,tgs_session_key,user_id,service_id,message_b):
    # creating message for TGS server by combining message b and service ID
    message = {'message_b': message_b,'service_id': service_id}
    message_string = json_string(message)
    message_c = en(message_string)
    ct = datetime.datetime.now() 
    ts = ct.timestamp()

    message_json = {'client_id':user_id,'timestamp':ts}
    message_d = json_string(message_json)
    print(tgs_session_key)
    print(b64decode(en(tgs_session_key)))
    tgs_session_key = b64decode(en(tgs_session_key))
    cipher = AES.new(tgs_session_key, AES.MODE_EAX)
    # encrypting using TGS session key
    ciphertext, tag = cipher.encrypt_and_digest(en(message_d))
    nonce = cipher.nonce
    ciphertext = en(ciphertext)
    tag = en(tag)
    nonce = en(nonce)
    data_json = {'cipher':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    return message_c,data_bytes

# retriving server session key
def retrive_server_session_key(tgs_session_key,messages):
    if 'key' in string_json(messages[0]):
        message_e = string_json(messages[1])
        message_f = string_json(messages[0])
    else :
        message_e = string_json(messages[0])
        message_f = string_json(messages[1])
    nonce = en(message_f['nonce'])
    tag = en(message_f['tag'])
    ciphertext = en(message_f['key'])
    try:
        cipher = AES.new(b64decode(en(tgs_session_key)), AES.MODE_EAX, nonce=b64decode(nonce))
        #  using TGS session key to retrieve server session key
        server_session_key = cipher.decrypt_and_verify(b64decode(ciphertext),b64decode(tag))
        server_session_key = dne(server_session_key)
        message = message_e
        return server_session_key, message
    except (ValueError, KeyError) as e:
        pass
    return None, None

# encrypting authenticator using client server session key
def encrypt_authenticator(key, message_e,user_id):
    ct = datetime.datetime.now() 
    ts = ct.timestamp()
    message_json = {'client_id':user_id,'timestamp':ts}
    message_d = json_string(message_json)
    key = key
    print(b64decode(en(key)))
    cipher = AES.new(b64decode(en(key)), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(en(message_d))
    nonce = cipher.nonce
    ciphertext = dn(ciphertext)
    tag = dn(tag)
    nonce = dn(nonce)
    data_json = {'cipher':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    message_e = en(json_string(message_e))
    return message_e,data_bytes,ts

# decrypting timestamp from server using server session key
def decrypt_ts(key, message):
    data = string_json(message[0])
    nonce = en(data['nonce'])
    tag = en(data['tag'])
    ciphertext = en(data['cipher'])
    key = en(key)
    try:
        cipher = AES.new(b64decode(key), AES.MODE_EAX, nonce=b64decode(nonce))
        ts = cipher.decrypt_and_verify(b64decode(ciphertext),b64decode(tag))
        ts = dn(ts)
        timestamp = ts
        return timestamp
    except (ValueError, KeyError):
        pass
    return

# encrypt RPC using session key
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
        data = dne(data)
        return data
    except (ValueError, KeyError):
        pass

def client_auth_server(user_id,password,service_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    # send user ID to Authentication server
    sock.sendto(user_id.encode('utf-8'), (AU_HOST, AU_PORT))
    count = 0
    messages = []
    # Wait for messages from server
    while count<2:
        data, server = sock.recvfrom(4096)
        if(server == (AU_HOST, AU_PORT)):
            count = count+1
            data = dne(data)
            messages.append(data)
    key = create_key(password)
    # retrive tgs session key and message b
    tgs_session_key, message_b = client_tgs_session(key,messages)

    # create message C using message B and Service ID
    # Create message D using user id, and timestamp
    message_c, message_d = encrypt_tgs_authorization(key,tgs_session_key,user_id,service_id,message_b)
    message_c = en(message_c)
    message_d = en(message_d)
    sock.sendto(message_c,(TGS_HOST, TGS_PORT))
    sock.sendto(message_d,(TGS_HOST, TGS_PORT))

    messages = []
    count = 0
    # wait for messages from TGS server
    while count<2:
        data, server = sock.recvfrom(4096)
        if(server == (TGS_HOST, TGS_PORT)):
            count = count+1
            messages.append(dne(data))
    # retrieve Server session key, and message E from the messages
    client_server_session_key, message_e = retrive_server_session_key(tgs_session_key, messages)
    # create and authenticator Message G(client ID and timestamp)
    message_e, message_g, ts = encrypt_authenticator(client_server_session_key,message_e,user_id)
    
    message_e = en(message_e)
    message_g = en(message_g)
    
    sock.sendto(message_e,(SERVER_HOST,int(SERVER_PORT)))
    sock.sendto(message_g,(SERVER_HOST,int(SERVER_PORT)))

    # waiting for reply from server
    messages = []
    count = 0
    while count<1:
        data, server = sock.recvfrom(4096)
        
        if(server == (SERVER_HOST,int(SERVER_PORT))):
            count = count+1
            messages.append(dne(data))
    # decrypting the timestamp sent by server
    sts = decrypt_ts(client_server_session_key,messages)
    sts = dne(b64decode(en(sts)))
    # verifying is timestamp matches
    if(sts==str(ts)):
        
        client_server_session_key = b64decode(en(client_server_session_key))
        
        sock.close()
        return client_server_session_key
    sock.close()
    return None
        



Folders = {"F1":"FS_1", "F2": "FS_2"}
FS_Ports = {"FS_1":9000, "FS_2":9001}
Client_PORT = PORT

# Return Session Key else None
# def authentication(File_server, FS_PORT):
#     return True

def SRPC(key, s, cmd ,data = "NIL"):
    result = {"pwd": None, "ls": None, "cp": None, "cat": None, "esc": None}
    
    rpc_str = cmd + " " + data
    rpc = encrypt_rpc(rpc_str,key)
    # sending
    s.send(rpc)
    # Recieve - update results dict

    res = s.recv(1024)
    res = dne(res)
    res = decrypt_rpc(res,key)


    result[cmd] = res

    return result

# present working directory
def pwd(key,s,data):
    result = SRPC(key,s, "pwd")
    print("\n", result["pwd"], "\n")
    return

# list elements
def ls(key,s,data):
    result = SRPC(key,s, "ls")
    print("\n", result["ls"], "\n")
    return

# copy File
def cp(key,s,data):
    if(len(data)<1):
        print("Missing arguments: Source Filename Destination Filename")
        return
    elif(len(data)<2):
        print("Missing argument: Destination Filename")
        return
    file_name = data[0] + " " + data[1]
    result = SRPC(key,s, "cp", file_name)
    # print("\n", "File Copied!", "\n")
    print("\n", result["cp"], "\n")
    return

# display File
def cat(key,s,data):
    if(len(data)<1):
        print("Missing argument: Filename")
        return
    file_name = data[0]
    result = SRPC(key,s, "cat", file_name)
    print("\n", result["cat"], "\n")
    return

# Close Session
def esc(key,s):
    # logic for closing session
    SRPC(key,s, "esc")
    return

Commands = {"pwd": pwd, "ls": ls, "cp": cp, "cat": cat, "esc": esc}

def main():
    print("Welcome to Secure RPC File System\n")

    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Client socket OK!")
    except socket.error as err:
        print ("socket creation failed -- Exiting")
        s.close()
        exit(0)

    try:
        s.bind(('', Client_PORT))
        print("Binding OK!")
    except:
        print ("Socket binding failed -- Exiting")
        s.close()
        exit(0)

    print("Following Folders are available: ")
    for folder in Folders.keys():
        print(folder)

    while(True):

        try:
            selected_folder = input("Select a Folder to continue or enter \"exit\" to exit: ")
            if selected_folder == "exit":
                break

            if selected_folder not in Folders:
                print("Invalid folder!\n")
                continue

            File_server = Folders[selected_folder]
            FS_PORT = FS_Ports[File_server]
            global SERVER_PORT
            SERVER_PORT = FS_PORT

            # Authentication
            key = client_auth_server(client,password,File_server)

            if not key:
                print(f"Not authorized to access Folder: {selected_folder}")
                continue

            # Connect with FS
            print("Establishing connection...")
            while(True):
                try:
                    print(FS_PORT)
                    print(type(FS_PORT))
                    s.connect(('127.0.0.1', FS_PORT))
                    break
                except Exception as err:
                    s.close()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    print(err)
                    continue

            print(f"Inside Folder: {selected_folder}")

            while(True):
                print("You are authorized to run the following commands: ")
                print("1. pwd - return present working directory")
                print("2. ls - list the files in the current directory")
                print("3. cp - copy one file onto another in the same folder")
                print("4. cat - display the contents of the file")
                print("5. esc - Exit folder\n")
                cmd = input("Enter command: ")
                cmd = cmd.split(" ")
                data = []
                try:
                    data = cmd[1:]
                except:
                    pass
                cmd = cmd[0]
                

                if Commands.get(cmd) is None:
                    print("Invalid Command! Please Enter a valid Command\n")
                    continue

                if cmd == "esc":
                    print("Escaping")
                    SRPC(key, s, "esc")
                    # s.shutdown(SHUT_RDWR)
                    s.close()
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        print("Client socket OK!")

                    except socket.error as err:
                        print ("socket creation failed -- Exiting")
                        s.close()
                        exit(0)

                    try:
                        s.bind(('', Client_PORT))
                        print("Binding OK!")
                    except:
                        print ("Socket binding failed -- Exiting")
                        s.close()
                        exit(0)
                    break

                Commands[cmd](key,s,data)

            print(f"Folder: {selected_folder} exited!\n")

        except Exception as err:
            print("ERROR: ", sys.exc_info()[0], "\n", err)
            s.close()
            exit(0)

if __name__ == "__main__":
    main()

    
    



    
