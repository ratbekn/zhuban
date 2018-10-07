from argparse import ArgumentTypeError
from dns_enums import ResourceRecordType
import unittest
import czhuban


class TestDomainName(unittest.TestCase):
    def test_too_short(self):
        s = 'a.a'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_too_long(self):
        s = 'ru.' * 84 + '.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_without_dots(self):
        s = 'googlecom'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_empty_subdomain(self):
        s = '.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_contain_invalid_symbols(self):
        s = 'he||&@.$om'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_label_start_with_number(self):
        s = '9google.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_label_start_with_hyphen(self):
        s = '-google.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_label_end_with_hyphen(self):
        s = 'google-.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)

    def test_too_long_label(self):
        s = 'o' * 64 + '.com'

        self.assertRaises(ArgumentTypeError, czhuban.domain_name, s)


class TestRecordType(unittest.TestCase):
    def test_not_exist_type(self):
        self.assertRaises(ArgumentTypeError, czhuban.record_type,
                          'ABRACADABRA')

    def test_A(self):
        record_type = czhuban.record_type('A')

        self.assertEqual(record_type, ResourceRecordType.A)

    def test_AAAA(self):
        record_type = czhuban.record_type('AAAA')

        self.assertEqual(record_type, ResourceRecordType.AAAA)

    def test_NS(self):
        record_type = czhuban.record_type('NS')

        self.assertEqual(record_type, ResourceRecordType.NS)


class TestParseArgs(unittest.TestCase):
    def test_only_hostname(self):
        args = ['google.com']

        parsed_args = czhuban.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')

    def test_hostname_and_type(self):
        args = ['google.com', '-t', 'A']

        parsed_args = czhuban.parse_args(args)

        self.assertEqual(parsed_args.hostname, 'google.com')
        self.assertEqual(parsed_args.type, ResourceRecordType.A)
