from dns_message import Query, Answer
import socket
import struct
import sys


def tcp_query(args, query):
    with socket.socket(socket.AF_INET, args.protocol) as s:
        s.settimeout(args.timeout)
        s.connect((args.server, args.port))

        qsize = struct.pack('!H', len(query))

        try:
            s.sendall(qsize)
            s.sendall(query)

            response = s.recv(1024)
        except socket.timeout:
            print('timed out')
            sys.exit(1)
        except socket.gaierror as error:
            print(error)
            sys.exit(1)

    size = struct.unpack('!H', response[:2])[0]
    return response[2:size + 2]


def udp_query(args, query):
    with socket.socket(socket.AF_INET, args.protocol) as s:
        s.settimeout(args.timeout)

        try:
            s.sendto(query, (args.server, args.port))
            response = s.recv(1024)
        except socket.timeout:
            print('timed out')
            sys.exit(1)
        except socket.gaierror as error:
            print(error)
            sys.exit(1)

    return response


query_method = {socket.SOCK_DGRAM: udp_query, socket.SOCK_STREAM: tcp_query}


def resolve(args):
    """
    Находит соответствующую hostname DNS запись типа record type

    :param args: объект с аргументами командной строки
    :return: DNS запись соответствующий данному hostname
    """

    query = Query(args.hostname, qtype=args.querytype).to_bytes()

    data = query_method[args.protocol](args, query)

    answer = Answer.from_bytes(data)

    return answer
