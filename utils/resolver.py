import socket
import struct
from dns.dns_enums import (
    QueryType, ResourceRecordType
)
from dns.dns_message import Query, Answer
from .zhuban_exceptions import (
    InvalidAnswer, InvalidServerResponse
)


def tcp_query(args, query):
    """
    Отправляет dns-запрос через TCP протокол

    :param args: арументы командной строки
    :param bytes query: объект bytes, содержащий запрос
    :raise socket.timeout: превышено время ожидания
    :raise socket.gaierror: ошибки связанные с адресом
    :return: объект bytes содержащий ответ от сервера
    """
    with socket.socket(socket.AF_INET, args.protocol) as s:
        s.settimeout(args.timeout)
        s.connect((args.server, args.port))

        qsize = struct.pack('!H', len(query))

        try:
            s.sendall(qsize + query)

            receive_size = struct.unpack('!H', s.recv(2))[0]

            response = s.recv(receive_size)
        except socket.timeout:
            raise
        except socket.gaierror:
            raise
        except ConnectionError:
            raise

    return response


def udp_query(args, query):
    """
    Отправляет dns-запрос через UDP протокол

    :param args: арументы командной строки
    :param bytes query: объект bytes, содержащий запрос
    :raise socket.timeout: превышено время ожидания
    :raise socket.gaierror: ошибки связанные с адресом
    :return: объект bytes содержащий ответ от сервера
    """
    with socket.socket(socket.AF_INET, args.protocol) as s:
        s.settimeout(args.timeout)

        try:
            s.sendto(query, (args.server, args.port))
            response = s.recv(1024)
        except socket.timeout:
            raise
        except socket.gaierror:
            raise

    return response


query_method = {socket.SOCK_DGRAM: udp_query, socket.SOCK_STREAM: tcp_query}


def resolve(args):
    """
    Находит IPv4 для данного hostname или наоборот

    :param args: объект с аргументами командной строки
    :return: объект Answer представляющий ответ от сервера
    """

    hostname = args.hostname
    resource_type = ResourceRecordType.A
    if args.inverse:
        ip = hostname.split('.')
        hostname = '.'.join(reversed(ip)) + '.in-addr.arpa'

        resource_type = ResourceRecordType.PTR

    query = Query(
        hostname, rr_type=resource_type,
        qtype=QueryType.STANDARD).to_bytes()

    try:
        response = query_method[args.protocol](args, query)
    except socket.timeout:
        raise
    except socket.gaierror:
        raise
    except ConnectionError:
        raise

    if len(response) > 512:
        raise InvalidServerResponse

    try:
        answer = Answer.from_bytes(response)
    except InvalidAnswer as e:
        raise InvalidServerResponse from e

    return answer
