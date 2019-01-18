import os
import sys

import pytest

from argparse import ArgumentTypeError

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from utils import arg_parser


incorrect_domains = {
    'too short': 'a.a',
    'too long': 'ru.' * 84 + '.com',
    'without dots': 'googlecom',
    'empty subdomain': '.com',
    'contain invalid symbols': 'he||&@$om',
    'start with hyphen': '-google.com',
    'end with hyphen': 'google-.com',
    'loo long label': 'o' * 64 + '.com'}


@pytest.mark.parametrize('incorrect_domain',
                         list(incorrect_domains.values()),
                         ids=list(incorrect_domains.keys()))
def test_if_incorrect_domain_raise_exception(incorrect_domain):
    """
    Если доменное имя неправильное,
    то arg_parser.domain_name(domain) должен выбрасывать ArgumentTypeError
    """
    with pytest.raises(ArgumentTypeError):
        arg_parser.domain_name(incorrect_domain)


def test_domain_non_ascii():
    s = 'винегрет.рус'

    assert arg_parser.domain_name(s) == s.encode('idna').decode('utf-8')


def test_domain_endswith_dots():
    s = 'google.com.'

    assert arg_parser.domain_name(s) == 'google.com'


incorrect_ips = {
    'letters': 'some',
    'too many dots': '8.8..4.4',
    'few dots': '192.57.7515',
    'not digits': '_.(.@.&'}


@pytest.mark.parametrize('incorrect_ip',
                         list(incorrect_ips.values()),
                         ids=list(incorrect_ips.keys()))
def test_if_incorrect_ip_raise_exception(incorrect_ip):
    """
    Если ipv4 не валидное,
    то arg_parser.ipv4 должен выбросить исключение ArgumentTypeError
    """
    with pytest.raises(ArgumentTypeError):
        arg_parser.ipv4(incorrect_ip)


incorrect_ports = {
    'not digit': 'a',
    'negative': '-5',
    'too large': '99999'}


@pytest.mark.parametrize('incorrect_port',
                         list(incorrect_ports.values()),
                         ids=list(incorrect_ports.keys()))
def test_if_incorrect_port_raise_exception(incorrect_port):
    """
    Если невалидный порт,
    то arg_parser.port должен выбросить исключение ArgumentTypeError
    """
    with pytest.raises(ArgumentTypeError):
        arg_parser.port(incorrect_port)


def test_port_valid():
    p = '80'

    assert arg_parser.port(p) == 80


incorrect_timeouts = {
    'not digit': '@',
    'negative': '-5',
    'zero': '0'}


@pytest.mark.parametrize('incorrect_timeout',
                         list(incorrect_timeouts),
                         ids=list(incorrect_timeouts))
def test_if_incorrect_timeout_raise_exception(incorrect_timeout):
    """
    Если невалидный таймаут,
    то arg_parser.timeout должен выбросить исключение ArgumentTypeError
    """
    with pytest.raises(ArgumentTypeError):
        arg_parser.timeout(incorrect_timeout)


def test_timeout_valid():
    t = '5'

    assert arg_parser.timeout(t) == 5


def test_protocol_tcp():
    protocol = 'tcp'

    assert arg_parser.protocol(protocol) == 'tcp'


def test_protocol_upd():
    protocol = 'udp'

    assert arg_parser.protocol(protocol) == 'udp'


def test_protocol_invalid():
    protocol = 'AAA'

    with pytest.raises(ArgumentTypeError):
        arg_parser.protocol(protocol)


def test_hostname():
    args = ['-s', '8.8.8.8', 'google.com']
    parsed_args = arg_parser.parse_args(args)

    assert parsed_args.hostname == 'google.com'


def test_hostname_if_no_args():
    args = []

    with pytest.raises(SystemExit):
        arg_parser.parse_args(args)
