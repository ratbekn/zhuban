from dns_message import (
    Header, encode_number, decode_number
)
from dns_enums import (
    MessageType, QueryType, ResponseType
)
import unittest


class TestEncodeNumber(unittest.TestCase):
    def test_negative(self):
        number = -1

        self.assertRaises(ValueError, encode_number, number)

    def test_zero(self):
        number = 0

        expected = b'\x00\x00'
        actual = encode_number(number)

        self.assertEqual(expected, actual)

    def test_positive(self):
        number = 27

        expected = b'\x00\x1b'
        actual = encode_number(number)

        self.assertEqual(expected, actual)

    def test_positive_1(self):
        number = 16

        expected = b'\x00\x10'
        actual = encode_number(number)

        self.assertEqual(expected, actual)


class TestDecodeNumber(unittest.TestCase):
    def test_zero(self):
        in_bytes = b'\x00\x00'

        expected = 0
        actual = decode_number(in_bytes)

        self.assertEqual(expected, actual)

    def test_positive(self):
        in_bytes = b'\x00\x1b'

        expected = 27
        actual = decode_number(in_bytes)

        self.assertEqual(expected, actual)

    def test_positive_1(self):
        in_bytes = b'\x00\x10'

        expected = 16
        actual = decode_number(in_bytes)

        self.assertEqual(expected, actual)


class TestHeaderInit(unittest.TestCase):
    def test_standard_query(self):
        header = Header(1337, MessageType.QUERY, 1)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_query_with_several_questions(self):
        header = Header(1337, MessageType.QUERY, 5)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 5)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_recursion_desired_query(self):
        header = Header(1337, MessageType.QUERY, 1, is_recursion_desired=True)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STANDARD)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, True)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_inverse_query(self):
        header = Header(1337, MessageType.QUERY, 1,
                        query_type=QueryType.INVERSE)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.INVERSE)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_status_query(self):
        header = Header(1337, MessageType.QUERY, 1,
                        query_type=QueryType.STATUS)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 1)

        self.assertEqual(header.query_type, QueryType.STATUS)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, False)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)

    def test_complex_query(self):
        header = Header(1337, MessageType.QUERY, 3,
                        query_type=QueryType.INVERSE,
                        is_recursion_desired=True)

        self.assertEqual(header.identifier, 1337)
        self.assertEqual(header.message_type, MessageType.QUERY)
        self.assertEqual(header.question_count, 3)

        self.assertEqual(header.query_type, QueryType.INVERSE)
        self.assertEqual(header.is_authority_answer, False)
        self.assertEqual(header.is_truncated, False)
        self.assertEqual(header.is_recursion_desired, True)
        self.assertEqual(header.is_recursion_available, False)
        self.assertEqual(header.response_type, ResponseType.NO_ERROR)
        self.assertEqual(header.answer_count, 0)
        self.assertEqual(header.authority_count, 0)
        self.assertEqual(header.additional_count, 0)


class TestHeaderEncodeFlags(unittest.TestCase):
    def test_standard_query(self):
        header = Header(1337, MessageType.QUERY, 0)

        expected = b'\x00\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_recursive_standard_query(self):
        header = Header(1337, MessageType.QUERY, 0, is_recursion_desired=True)

        expected = b'\x01\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_inverse_query(self):
        header = Header(1337, MessageType.QUERY, 0,
                        query_type=QueryType.INVERSE)

        expected = b'\x08\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_recursive_inverse_query(self):
        header = Header(1337, MessageType.QUERY, 0,
                        query_type=QueryType.INVERSE,
                        is_recursion_desired=True)

        expected = b'\t\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)

    def test_simple_answer(self):
        header = Header(1337, MessageType.RESPONSE, 0)

        expected = b'\x80\x00'
        actual = header._encode_flags()

        self.assertEqual(expected, actual)


class TestHeaderToBytes(unittest.TestCase):
    def test_standard_query(self):
        header = Header(256, MessageType.QUERY, 1)

        expected = b'\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)

    def test_query_with_two_questions(self):
        header = Header(256, MessageType.QUERY, 2)

        expected = b'\x01\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)

    def test_query_with_several_questions(self):
        header = Header(256, MessageType.QUERY, 5)

        expected = b'\x01\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00'
        actual = header.to_bytes()

        self.assertEqual(expected, actual)


class TestHeaderFromBytes(unittest.TestCase):
    def equal_headers(self, expected, actual):
        self.assertEqual(expected.identifier, actual.identifier)

        self.assertEqual(expected.message_type, actual.message_type)
        self.assertEqual(expected.query_type, actual.query_type)
        self.assertEqual(expected.is_authority_answer,
                         actual.is_authority_answer)
        self.assertEqual(expected.is_truncated, actual.is_truncated)
        self.assertEqual(expected.is_recursion_desired,
                         actual.is_recursion_desired)
        self.assertEqual(expected.is_recursion_available,
                         actual.is_recursion_available)
        self.assertEqual(expected.response_type, actual.response_type)

        self.assertEqual(expected.question_count, actual.question_count)
        self.assertEqual(expected.answer_count, actual.answer_count)
        self.assertEqual(expected.authority_count, actual.authority_count)
        self.assertEqual(expected.additional_count, actual.additional_count)

    def test_no_error_answer(self):
        in_bytes = b'\x01\x00\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00'

        expected = Header(256, MessageType.RESPONSE, 1, answer_count=1)
        actual = Header.from_bytes(in_bytes, 0).header

        self.equal_headers(expected, actual)

    def test_no_error_rd_answer(self):
        in_bytes = b'\x01\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

        expected = Header(256, MessageType.RESPONSE, 1, answer_count=1,
                          is_recursion_desired=True,
                          is_recursion_available=True)
        actual = Header.from_bytes(in_bytes, 0).header

        self.equal_headers(expected, actual)
