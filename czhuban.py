import argparse
import re
import sys
from dns_enums import (
    QueryType
)

valid_domain_name_pattern = re.compile(
    r'^(?=.{4,253}$)'
    r'((([a-zA-Z])|([a-zA-Z][a-zA-Z0-9])'
    r'|([a-zA-Z][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))\.)+'
    r'([a-zA-Z]{2,18}|(xn--[a-zA-Z0-9]{4,24}))$'
)


def domain_name(s):
    """
    Проверяет является ли переданная строка валидным доменным именем

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: исходную строку, если она является валидным доменным именем
    """
    if valid_domain_name_pattern.match(s) is None:
        msg = 'задано невалидное доменное имя'
        raise argparse.ArgumentTypeError(msg)
    return s


def record_type(s):
    """
    Проверяет является ли переданная строка валидным типом DNS-записи

    :param s: строковое представление типа
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: QueryType представляющий тип DNS-записи
    """
    if s not in QueryType.__members__:
        msg = 'задан неправильный тип DNS-записи: ' + s
        raise argparse.ArgumentTypeError(msg)
    return QueryType[s]


def parse_args(args):
    """
    Парсит переданные аргументы командной строки

    :return: argparse.Namespace объект с атрибутами соответствующими аргументам
    """
    parser = argparse.ArgumentParser(description='Определяет IP адрес '
                                                 'компьютера по его '
                                                 'доменному имени')

    parser.add_argument('hostname', type=domain_name,
                        help='доменное имя. состоит из меток разделенных '
                             'точкой. каждая метка - слово состоящее из букв '
                             'латинского алфавита, цифр и знака дефис. метка '
                             'должна начинается буквой латинского алфавита и '
                             'заканчиваться буквой латинского алфавита либо '
                             'цифрой и быть длиной от 1 до 63 букв. общая '
                             'длина доменного имени не должна превышать 253 '
                             'букв включая точки')

    parser.add_argument('-t', '--type', type=record_type,
                        default=QueryType.A,
                        help='тип требуемой DNS-записи. возможные значения: '
                             'A - адрес IPv4; AAAA - адрес IPv6; '
                             'NS - адреса DNS-серверов, ответственных за зону')

    parsed_args = parser.parse_args(args)

    return parsed_args
