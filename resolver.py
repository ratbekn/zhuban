import socket
import struct
import sys
from dns_enums import (
    QueryType, ResourceRecordType
)
from dns_message import Query, Answer


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
    Находит соответствующую hostname адрес IPv4

    :param args: объект с аргументами командной строки
    :return: список IPv4 соответствующие данному hostname
    """

    query = Query(args.hostname, qtype=QueryType.STANDARD).to_bytes()

    data = query_method[args.protocol](args, query)

    answer = Answer.from_bytes(data)

    return answer


def resolve_inverse(args):
    """
    Находит соответствующую IPv4 доменное имя

    :param args:
    :return: доменные имена соответсвующие данному IPv4
    """
    ip = args.hostname.split('.')
    ptr_name = '.'.join(reversed(ip)) + '.in-addr.arpa'

    query = Query(ptr_name,
                  rr_type=ResourceRecordType.PTR,
                  qtype=QueryType.STANDARD).to_bytes()

    data = query_method[args.protocol](args, query)

    answer = Answer.from_bytes(data)

    return answer
