import socket
import unittest
from argparse import Namespace
from dns.dns_message import (
    Query, Answer
)
from unittest import mock
from utils import (
    resolver
)
from utils.zhuban_exceptions import InvalidServerResponse


class TestSendMessage(unittest.TestCase):
    def setUp(self):
        self.argv = Namespace(
            hostname='yandex.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            ipv6=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_empty_server_response(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = b''
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        self.assertRaises(InvalidServerResponse, resolver.send_query, self.argv)

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_too_long_message(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = bytearray(513)
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        self.assertRaises(InvalidServerResponse, resolver.send_query, self.argv)

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_invalid_server_response_1(
            self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = \
            b'\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        self.assertRaises(InvalidServerResponse, resolver.send_query, self.argv)

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_A(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = \
            b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06yandex' \
            b'\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00' \
            b'\x00\x00\x00\x04\xd5\xb4\xcc\x3e'
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        answer = resolver.send_query(self.argv)

        self.assertEqual('yandex.com', answer.answers[0].name)
        self.assertEqual('213.180.204.62', answer.answers[0].data.ip)

    @mock.patch('utils.resolver.udp_query', side_effect=socket.timeout)
    @mock.patch('utils.resolver.query_method')
    def test_timeout(self, mock_query_method, mock_udp_query):
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        self.assertRaises(socket.timeout, resolver.send_query, self.argv)

    @mock.patch('utils.resolver.udp_query', side_effect=socket.gaierror)
    @mock.patch('utils.resolver.query_method')
    def test_gaierror(self, mock_query_method, mock_udp_query):
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        self.assertRaises(socket.gaierror, resolver.send_query, self.argv)


class TestUDPQuery(unittest.TestCase):
    def setUp(self):
        self.argv = Namespace(
            hostname='yandex.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )
        self.bytes_ = Query('yandex.com').to_bytes()

    @mock.patch(
        'socket.socket.recv',
        return_value=b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        b'\x06yandex\x03com\x00\x00\x01\x00\x01'
        b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xd5\xb4\xcc\x3e'
    )
    def test_A(self, mock_socket_recv):
        response = resolver.udp_query(self.argv, self.bytes_)
        answer = Answer.from_bytes(response)

        self.assertEqual(answer.answers[0].name, 'yandex.com')
        self.assertEqual(answer.answers[0].data.ip, '213.180.204.62')

    @mock.patch('socket.socket.recv', side_effect=socket.timeout)
    def test_timeout(self, mock_socket_recv):
        self.assertRaises(
            socket.timeout, resolver.udp_query, self.argv, self.bytes_
        )

    @mock.patch('socket.socket.recv', side_effect=socket.gaierror)
    def test_gaierror(self, mock_socket_recv):
        self.assertRaises(
            socket.gaierror, resolver.udp_query, self.argv, self.bytes_
        )


class TestTCPQuery(unittest.TestCase):
    def setUp(self):
        self.argv = Namespace(
            hostname='google.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            ivp6=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )
        self.bytes_ = Query('google.com').to_bytes()

    def mock_recv(bufsize):
        size = b'\x00\x2c'
        response = \
            b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' \
            b'\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c' \
            b'\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x4a\x7d\xe8\xe7'
        if bufsize == 2:
            return size
        else:
            return response

    @mock.patch('socket.socket.recv', side_effect=mock_recv)
    def test_A(self, mock_socket_recv):
        response = resolver.tcp_query(self.argv, self.bytes_)
        answer = Answer.from_bytes(response)

        self.assertEqual(answer.questions[0].name, 'google.com')
        self.assertEqual(answer.answers[0].data.ip, '74.125.232.231')

    @mock.patch('socket.socket.recv', side_effect=socket.timeout)
    def test_timeout(self, mock_socket_recv):
        self.assertRaises(
            socket.timeout, resolver.tcp_query, self.argv, self.bytes_
        )

    @mock.patch('socket.socket.recv', side_effect=socket.gaierror)
    def test_gaierror(self, mock_socket_recv):
        self.assertRaises(
            socket.gaierror, resolver.tcp_query, self.argv, self.bytes_
        )
