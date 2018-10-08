from dns_message import Query, Answer
import socket


def resolve(hostname, record_type):
    """
    Находит соответствующую hostname DNS запись типа record type

    :param hostname: имя хоста для которого нужно найти запись
    :param record_type: тип требуемой DNS записи
    :return: DNS запись соответствующий данному hostname
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    s.connect(('8.8.8.8', 53))

    query = Query(hostname, is_recursion_desired=True, rr_type=record_type)
    s.send(query.to_bytes())
    response = s.recv(1024)

    answer = Answer.from_bytes(response)

    return answer
