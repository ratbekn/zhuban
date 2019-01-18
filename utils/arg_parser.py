import argparse
import ipaddress
import re
import sys
from argparse import RawTextHelpFormatter
from utils import resolver


valid_domain_name_pattern = re.compile(
    r'^(?=.{1,253}$)'
    r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b'
)


valid_ipv4_pattern = re.compile(
    r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
)


valid_ipv6_pattern = re.compile(
    r'^(?:[a-fA-F0-9]{0,4}:){7}[a-fA-F0-9]{0,4}$'
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

    try:
        s.encode('ascii')
    except UnicodeEncodeError:
        s = s.encode('idna').decode('utf-8')

    if valid_domain_name_pattern.match(s) is None:
        msg = 'задано невалидное доменное имя'
        raise argparse.ArgumentTypeError(msg)
    return s


def ipv4(s):
    """
    Проверяет является ли переданная строка валидным ipv4 адресом

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: исходную строку, если она является валидным доменным имененм
    """
    if valid_ipv4_pattern.match(s) is None:
        msg = 'задан невалидный ipv4'
        raise argparse.ArgumentTypeError(msg)
    return s


def ipv6(s):
    """
    Проверяет является ли переданная строка валидным ipv6 адресом

    :param s: строка для проверки
    :raise argparse.ArgumentTypeError(msg): если строка не является валидным
    :return: ipaddress.IPv6Address, если она является валидным доменным имененм
    """
    try:
        res = ipaddress.IPv6Address(s)
    except ipaddress.AddressValueError:
        msg = 'задан невалидный ipv6'
        raise argparse.ArgumentTypeError(msg)
    return res


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
    protocols = {'udp', 'tcp'}
    if s not in protocols:
        msg = 'задан неверный протокол. выберите между TCP и UDP'
        raise argparse.ArgumentTypeError(msg)
    return s


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
        help='Режим отображения IPv4 в доменное имя\n'
             '(default: %(default)s)\n\n')
    is_inverse = '-i' in argv or '--inverse' in argv

    parser.add_argument(
        '-6', '--ipv6', default=False, action='store_true',
        help='Режим для определения адресов IPv6\n'
             '(default: %(default)s)\n\n'
    )
    is_ipv6 = '-6' in argv or '--ipv6' in argv

    parser.add_argument(
        '-d', '--dump', default=False, action='store_true',
        help='Режим получения дампа - всех поддоменов в домене.\n'
             'Работает, если у вас есть доступ к Name Server\'у домена т.е\n'
             'сервер разрешает axfr запросы с вашего IP\n'
             '(default: %(default)s)\n\n'
    )

    parser.add_argument(
        '-P', '--protocol', type=protocol, default='udp',
        help='Протокол транспортного уровня для общениия с DNS сервером.\n'
             '(default: udp)\n\n')

    parser.add_argument(
        '-t', '--timeout', type=timeout, default=10,
        help='время ожидания ответа от сервера в секундах \n'
             'Должен быть больше 0 секунд.\n(default: %(default)s)\n\n')

    parser.add_argument(
        '-s', '--server', type=ipv4, metavar='ADDRESS',
        help='Адрес DNS-сервера.\n(default: %(default)s)\n\n')

    parser.add_argument(
        '-p', '--port', type=port, default=53,
        help='Порт сервера\n(default: %(default)s)\n\n')

    hostname_type = domain_name
    if is_inverse:
        hostname_type = ipv4 if not is_ipv6 else ipv6

    parser.add_argument(
        'hostname', type=hostname_type,
        help='если включён режим -i, то IPv4, иначе доменное имя, которое\n'
             'состоит из меток разделенных точкой.\nкаждая метка - слово '
             'состоящее из букв латинского алфавита, цифр и знака дефис.\n'
             'метка должна начинается буквой латинского алфавита и '
             'заканчиваться буквой латинского алфавита\nлибо цифрой и быть '
             'длиной от 1 до 63 букв.\nобщая длина доменного имени не должна '
             'превышать 253 букв включая точки\n\n')

    parser.set_defaults(func=resolver.resolve)

    if len(argv) == 0:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args(argv)

    if args.dump and (args.inverse or args.ipv6):
        parser.print_usage(sys.stderr)
        print('czhuban.py: error: -d и -i|-6 взаимоисключающие')
        sys.exit(1)

    return args
