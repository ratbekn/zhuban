import socket
import sys
from dns_message import Query, Answer
from dns_enums import ResourceRecordType


def resolve(args):
    """
    Находит DNS запись типа record type соответствующую hostname

    :param args: объект с аргументами командной строки
    :return: DNS запись соответствующий данному hostname
    """
    query = Query(args.hostname, is_recursion_desired=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(args.timeout)
    try:
        s.sendto(query.to_bytes(), (args.server, args.port))
    except socket.gaierror as ex:
        print(ex)
        sys.exit(1)

    try:
        response = s.recv(1024)
    except socket.timeout as ex:
        print("Истекло время ожидания ответа от сервера. Убедитесь, "
              "что правильно указан адрес и порт DNS-сервера и попробуйте "
              "увеличить время"
              "ожидания. Для помощи --help")
        sys.exit(1)

    s.close()

    answer = Answer.from_bytes(response)

    a_answers = filter(lambda rr: rr.type_ == ResourceRecordType.A,
                       answer.answers)

    return list(a_answers)
