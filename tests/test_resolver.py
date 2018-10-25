import socket
import unittest
from argparse import Namespace
from unittest import mock
from utils import (
    resolver
)
from utils.zhuban_exceptions import InvalidServerResponse


class TestResolve(unittest.TestCase):
    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_invalid_server_response(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = b''
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        argv = Namespace(
            hostname='yandex.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )

        self.assertRaises(InvalidServerResponse, resolver.resolve, argv)

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_too_long_message(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = bytearray(513)
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        argv = Namespace(
            hostname='yandex.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )

        self.assertRaises(InvalidServerResponse, resolver.resolve, argv)

    @mock.patch('utils.resolver.udp_query')
    @mock.patch('utils.resolver.query_method')
    def test_invalid_server_response(self, mock_query_method, mock_udp_query):
        mock_udp_query.return_value = b'\x00\x00\x00\x00\x00\x01\x00\x01\x00' \
                                      b'\x00\x00\x00\x00\x00\x00'
        d = {socket.SOCK_DGRAM: mock_udp_query}
        mock_query_method.__getitem__.side_effect = d.__getitem__

        argv = Namespace(
            hostname='yandex.com',
            server='8.8.8.8',
            port=53,
            inverse=False,
            protocol=socket.SOCK_DGRAM,
            timeout=10
        )

        self.assertRaises(InvalidServerResponse, resolver.resolve, argv)
