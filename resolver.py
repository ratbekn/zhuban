from dns_message import Query, Answer
import socket


def resolve(args):
    """
    Находит соответствующую hostname DNS запись типа record type

    :param args: объект с аргументами командной строки
    :return: DNS запись соответствующий данному hostname
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(args.timeout)
    s.connect((args.server, args.port))

    query = Query(args.hostname, qtype=args.querytype)
    s.send(query.to_bytes())
    response = s.recv(1024)

    answer = Answer.from_bytes(response)

    return answer
