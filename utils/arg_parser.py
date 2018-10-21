import argparse
import re
import sys
from argparse import RawTextHelpFormatter
from socket import SOCK_DGRAM, SOCK_STREAM
from utils import resolver


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


def protocol(s):
    """
    Проверяет является ли переданная строка валиным протоколом

    :param s: строковое представление протокола
    :raise argparse.ArgumentTypeError(msg): если строка не валидна
    :return: socket.SOCK_DGRAM либо socket.SOCK_STREAM
    """
    protocols = {'UDP': SOCK_DGRAM, 'TCP': SOCK_STREAM}
    if s not in protocols:
        msg = 'задан неверный протокол. выберите между TCP и UDP'
        raise argparse.ArgumentTypeError(msg)
    return protocols[s]


def parse_args(argv):
    """
    Парсит переданные аргументы командной строки

    :return: argparse.Namespace объект с атрибутами соответствующими аргументам
    """
    parser = argparse.ArgumentParser(
        description='Программа, обеспечивающая определение IPv4 адреса узла по'
                    ' его доменному имени и наоборот',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '-i', '--inverse', default=False, action='store_true',
        help='Включает режим отображения IPv4 в доменное имя\n'
             '(default: %(default)s)\n\n')
    is_inverse = '-i' in argv or '--inverse' in argv

    parser.add_argument(
        '-P', '--protocol', type=protocol, default=SOCK_DGRAM,
        help='Протокол транспортного уровня для общениия с DNS сервером.\n'
             '(default: UDP)\n\n')

    parser.add_argument(
        '-t', '--timeout', type=timeout, default=10,
        help='время ожидания ответа от сервера в секундах \n'
             'Должен быть больше 0 секунд.\n(default: %(default)s)\n\n')

    parser.add_argument(
        '-s', '--server', type=ip, default='8.8.8.8', metavar='ADDRESS',
        help='Адрес DNS-сервера.\n(default: %(default)s)\n\n')

    parser.add_argument(
        '-p', '--port', type=port, default=53,
        help='Порт сервера\n(default: %(default)s)\n\n')

    parser.add_argument(
        'hostname', type=ip if is_inverse else domain_name,
        help='если включён режим -i, то IPv4, иначе доменное имя, которое\n'
             'состоит из меток разделенных точкой.\nкаждая метка - слово '
             'состоящее из букв латинского алфавита, цифр и знака дефис.\n'
             'метка должна начинается буквой латинского алфавита и '
             'заканчиваться буквой латинского алфавита\nлибо цифрой и быть '
             'длиной от 1 до 63 букв.\nобщая длина доменного имени не должна '
             'превышать 253 букв включая точки\n\n')

    parser.set_defaults(
        func=resolver.resolve_inverse if is_inverse else resolver.resolve)

    if len(argv) == 0:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args(argv)
