import argparse
import re
from dns_enums import (
    ResourceRecordType
)
from argparse import RawTextHelpFormatter


valid_domain_name_pattern = re.compile(
    r'^(?=.{4,253}$)'
    r'((([a-zA-Z])|([a-zA-Z][a-zA-Z0-9])'
    r'|([a-zA-Z][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))\.)+'
    r'([a-zA-Z]{2,18}|(xn--[a-zA-Z0-9]{4,24}))$'
)

valid_ip_pattern = re.compile(
    r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
)


def domain_name(s):
    """
    Проверяет является ли переданная строка валидным доменным именем

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: исходную строку, если она является валидным доменным именем
    """
    if s.endswith('.'):
        s = s[:-1]

    if valid_domain_name_pattern.match(s) is None:
        msg = 'задано невалидное доменное имя'
        raise argparse.ArgumentTypeError(msg)
    return s


def ip(s):
    """
    Проверяет является ли переданная строка валидным ip адресом

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: исходную строку, если она является валидным доменным имененм
    """
    if valid_ip_pattern.match(s) is None:
        msg = 'задан невалидный ip'
        raise argparse.ArgumentTypeError(msg)
    return s


def port(s):
    """
    Проверяет является ли переданная строка валидным портом

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: числовое значение порта, если она является валидным портом
    """
    if not s.isdigit() or int(s) not in range(1, 65535 + 1):
        msg = 'задан невалидный порт'
        raise argparse.ArgumentTypeError(msg)
    return int(s)


def timeout(s):
    """
    Проверяет является ли переданная строка валидным timeout

    :param s: строковое значение timeout
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: числовое значение timeout
    """
    if not s.isdigit() or int(s) < 1:
        msg = 'задан невалидный timeout'
        raise argparse.ArgumentTypeError(msg)
    return int(s)


def record_type(s):
    """
    Проверяет является ли переданная строка валидным типом DNS-записи

    :param s: строковое представление типа
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: QueryType представляющий тип DNS-записи
    """
    if s not in ResourceRecordType.__members__:
        msg = 'задан неправильный тип DNS-записи: ' + s
        raise argparse.ArgumentTypeError(msg)
    return ResourceRecordType[s]


def parse_args(args):
    """
    Парсит переданные аргументы командной строки

    :return: argparse.Namespace объект с атрибутами соответствующими аргументам
    """
    parser = argparse.ArgumentParser(description='Возвращает DNS-запись '
                                                 'требуемого типа '
                                                 '(по умолчанию тип A - '
                                                 'IPv4), '
                                                 'по соответствующему '
                                                 'доменному имени',
                                     formatter_class=RawTextHelpFormatter)

    parser.add_argument('hostname', type=domain_name,
                        help='доменное имя. состоит из меток разделенных\n'
                             'точкой. каждая метка - слово состоящее из букв\n'
                             'латинского алфавита, цифр и знака дефис. метка\n'
                             'должна начинается буквой латинского алфавита и\n'
                             'заканчиваться буквой латинского алфавита либо\n'
                             'цифрой и быть длиной от 1 до 63 букв. общая\n'
                             'длина доменного имени не должна превышать 253\n'
                             'букв включая точки')

    parser.add_argument('-qt', '--querytype', type=str,
                        choices=['STANDARD', 'INVERSE', 'STATUS'],
                        default='STANDARD',
                        help='Тип запроса.\n'
                             '(default: %(default)s)')

    parser.add_argument('-rt', '--rtype', type=record_type,
                        default=ResourceRecordType.A,
                        help='тип требуемой DNS-записи.\n'
                             'возможные значения:\n'
                             'A - адрес IPv4;\n'
                             'NS - адреса DNS-серверов, ответственных за '
                             'зону;\n'
                             'AAAA - адрес IPv6;\n'
                             '(default: A)')

    parser.add_argument('-s', '--server', type=ip, default='8.8.8.8',
                        metavar='ADDRESS',
                        help='IPv4 адрес DNS-сервера.\n'
                             '(default: %(default)s)')

    parser.add_argument('-p', '--port', type=port, default=53,
                        help='Порт сервера.\n'
                             '(default: %(default)s)')

    parser.add_argument('-prot', '--protocol', type=str,
                        choices=['TCP', 'UDP'],
                        default='UDP',
                        help='Протокол транспортного уровня для общениия с '
                             'DNS сервером.\n'
                             '(default: %(default)s)')

    parser.add_argument('-t', '--timeout', type=timeout, default=30,
                        help='время ожидания ответа от сервера в секундах '
                             'при использовании протокола UDP.\n'
                             'Должен быть больше 0 секунд.\n'
                             '(default: %(default)s)')

    parsed_args = parser.parse_args(args)

    return parsed_args
