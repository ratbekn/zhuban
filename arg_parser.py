import argparse
import re
from dns_enums import (
    ResourceRecordType, QueryType
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


def query_type(s):
    """
    Проверяет является ли переданная строка валидным типом DNS-запроса

    :param s: строковое представление типа запроса
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return QueryType представляющий тип запроса
    """
    if s not in QueryType.__members__:
        msg = 'задан неправильным тип DNS-запроса'
        raise argparse.ArgumentTypeError(msg)
    return QueryType[s]


def parse_args(args):
    """
    Парсит переданные аргументы командной строки

    :return: argparse.Namespace объект с атрибутами соответствующими аргументам
    """
    parser = argparse.ArgumentParser(description='Программа, обеспечивающая '
                                                 'определение IPv4 адреса '
                                                 'узла по его доменному имени',
                                     formatter_class=RawTextHelpFormatter)

    parser.add_argument('hostname', type=domain_name,
                        help='доменное имя.\nсостоит из меток разделенных '
                             'точкой.\nкаждая метка - слово состоящее из букв '
                             'латинского алфавита, цифр и знака дефис.\nметка '
                             'должна начинается буквой латинского алфавита и '
                             'заканчиваться буквой латинского алфавита\nлибо '
                             'цифрой и быть длиной от 1 до 63 букв.\nобщая '
                             'длина доменного имени не должна превышать 253 '
                             'букв включая точки')

    parser.add_argument('server', type=ip, default='8.8.8.8',
                        metavar='server',
                        help='IPv4 адрес DNS-сервера.\n')

    parser.add_argument('-qt', '--querytype', type=query_type,
                        default=QueryType.STANDARD,
                        help='Тип запроса. STANDARD либо INVERSE\n'
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
