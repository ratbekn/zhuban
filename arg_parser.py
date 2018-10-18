import argparse
import re
import resolver
from argparse import RawTextHelpFormatter
from socket import SOCK_DGRAM, SOCK_STREAM


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


def parse_args(args):
    """
    Парсит переданные аргументы командной строки

    :return: argparse.Namespace объект с атрибутами соответствующими аргументам
    """
    parser = argparse.ArgumentParser(description='Программа, обеспечивающая '
                                                 'определение IPv4 адреса '
                                                 'узла по его доменному имени',
                                     formatter_class=RawTextHelpFormatter)
    subparsers = parser.add_subparsers(title='Тип запроса',
                                       description='стандартный для '
                                                   'получения IPv4 адреса по '
                                                   'доменному имени либо '
                                                   'инверсивный для получения '
                                                   'доменного имени по IPv4')

    parser_standard = subparsers.add_parser('standard', aliases=['s'],
                                            help='стандартный запрос. '
                                                 'help: python czhuban.py s '
                                                 '-h')

    parser_standard.add_argument('hostname', type=domain_name,
                                 help='доменное имя.\nсостоит из меток '
                                      'разделенных точкой.\nкаждая метка - '
                                      'слово состоящее из букв латинского '
                                      'алфавита, цифр и знака дефис.\nметка '
                                      'должна начинается буквой латинского '
                                      'алфавита и заканчиваться буквой '
                                      'латинского алфавита\nлибо цифрой и быть'
                                      ' длиной от 1 до 63 букв.\nобщая длина '
                                      'доменного имени не должна превышать '
                                      '253 букв включая точки\n \n')
    parser_standard.set_defaults(func=resolver.resolve)

    parser_inverse = subparsers.add_parser('inverse', aliases=['i'],
                                           help='инверсивный запрос. '
                                                'help: python czhuban.py i -h')

    parser_inverse.add_argument('hostip', type=ip,
                                help='IPv4 адрес хоста')
    parser_inverse.set_defaults(func=resolver.resolve_inverse)

    parser.add_argument('-prot', '--protocol', type=protocol,
                        default=SOCK_DGRAM,
                        help='Протокол транспортного уровня для общениия с '
                             'DNS сервером.\n'
                             '(default: UDP)\n \n')

    parser.add_argument('-t', '--timeout', type=timeout, default=10,
                        help='время ожидания ответа от сервера в секундах '
                             'при использовании протокола UDP.\n'
                             'Должен быть больше 0 секунд.\n'
                             '(default: %(default)s)\n \n')

    parser.add_argument('-s', '--server', type=ip, default='8.8.8.8',
                        metavar='ADDRESS',
                        help='IPv4 адрес DNS-сервера.\n')

    parser.add_argument('-p', '--port', type=port, default=53,
                        help='Порт сервера\n'
                             '(default: %(default)s)\n \n')

    return parser.parse_args(args)
