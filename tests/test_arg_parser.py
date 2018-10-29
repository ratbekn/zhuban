import os
import socket
import sys
import unittest
from argparse import ArgumentTypeError

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             os.path.pardir))
from utils import arg_parser


class TestDomainName(unittest.TestCase):
    def test_too_short(self):
        s = 'a.a'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_too_long(self):
        s = 'ru.' * 84 + '.com'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_without_dots(self):
        s = 'googlecom'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_endswith_dots(self):
        s = 'google.com.'

        self.assertEqual('google.com', arg_parser.domain_name(s))

    def test_empty_subdomain(self):
        s = '.com'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_contain_invalid_symbols(self):
        s = 'he||&@.$om'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_label_start_with_hyphen(self):
        s = '-google.com'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_label_end_with_hyphen(self):
        s = 'google-.com'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_too_long_label(self):
        s = 'o' * 64 + '.com'

        self.assertRaises(ArgumentTypeError, arg_parser.domain_name, s)

    def test_non_ascii(self):
        s = 'винегрет.рус'

        self.assertEqual(
            s.encode('idna').decode('utf-8'), arg_parser.domain_name(s))


class TestIP(unittest.TestCase):
    def test_letters(self):
        s = 'some'

        self.assertRaises(ArgumentTypeError, arg_parser.ipv4, s)

    def test_too_many_dots(self):
        s = '8.8..4.4'

        self.assertRaises(ArgumentTypeError, arg_parser.ipv4, s)

    def test_few_dots(self):
        s = '192.57.7415'

        self.assertRaises(ArgumentTypeError, arg_parser.ipv4, s)

    def test_not_digits(self):
        s = '_.{.@.&'

        self.assertRaises(ArgumentTypeError, arg_parser.ipv4, s)


class TestPort(unittest.TestCase):
    def test_not_digit(self):
        p = 'a'

        self.assertRaises(ArgumentTypeError, arg_parser.port, p)

    def test_negative(self):
        p = '-5'

        self.assertRaises(ArgumentTypeError, arg_parser.port, p)

    def test_too_large(self):
        p = '99999'

        self.assertRaises(ArgumentTypeError, arg_parser.port, p)

    def test_valid(self):
        p = '80'

        self.assertEqual(80, arg_parser.port(p))


class TestTimeout(unittest.TestCase):
    def test_not_digit(self):
        t = '@'

        self.assertRaises(ArgumentTypeError, arg_parser.timeout, t)

    def test_negative(self):
        t = '-5'

        self.assertRaises(ArgumentTypeError, arg_parser.timeout, t)

    def test_zero(self):
        t = '0'

        self.assertRaises(ArgumentTypeError, arg_parser.timeout, t)

    def test_valid(self):
        t = '5'

        self.assertEqual(5, arg_parser.timeout(t))


class TestProtocol(unittest.TestCase):
    def test_tcp(self):
        protocol = 'TCP'

        self.assertEqual(socket.SOCK_STREAM, arg_parser.protocol(protocol))

    def test_udp(self):
        protocol = 'UDP'

        self.assertEqual(socket.SOCK_DGRAM, arg_parser.protocol(protocol))

    def test_invalid_protocol(self):
        protocol = 'AAA'

        self.assertRaises(ArgumentTypeError, arg_parser.protocol, protocol)


class TestParseArgs(unittest.TestCase):
    def test_only_hostname(self):
        args = ['-s', '8.8.8.8', 'google.com']

        parsed_args = arg_parser.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')

    def test_hostname(self):
        args = ['-s', '8.8.8.8', 'google.com']

        parsed_args = arg_parser.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')

    def test_no_args(self):
        args = []

        self.assertRaises(SystemExit, arg_parser.parse_args, args)
