import unittest
import arg_parser
from argparse import ArgumentTypeError
from dns_enums import (
    ResourceRecordType
)


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

    def test_label_start_with_number(self):
        s = '9google.com'

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


class TestIP(unittest.TestCase):
    def test_letters(self):
        s = 'some'

        self.assertRaises(ArgumentTypeError, arg_parser.ip, s)

    def test_too_many_dots(self):
        s = '8.8..4.4'

        self.assertRaises(ArgumentTypeError, arg_parser.ip, s)

    def test_few_dots(self):
        s = '192.57.7415'

        self.assertRaises(ArgumentTypeError, arg_parser.ip, s)

    def test_not_digits(self):
        s = '_.{.@.&'

        self.assertRaises(ArgumentTypeError, arg_parser.ip, s)


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


class TestParseArgs(unittest.TestCase):
    def test_only_hostname(self):
        args = ['-s', '8.8.8.8', 's', 'google.com']

        parsed_args = arg_parser.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')

    def test_hostname(self):
        args = ['-s', '8.8.8.8', 's', 'google.com']

        parsed_args = arg_parser.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')
