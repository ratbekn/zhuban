from collections import namedtuple
from dns_enums import (
    MessageType, QueryType, ResponseType
)
import struct


MAX_DOUBLE_BYTE_NUMBER = 65535


def encode_number(number):
    """
    Кодирует целое число в 2 байта с порядком байт big-endian

    :param int number: целое число, которое нужно закодировать
    :raise ValueError: если число не поместиться в 2 байта
    :return: объект bytes содержащий число
    """
    if 0 <= number < MAX_DOUBLE_BYTE_NUMBER:
        return struct.pack('!H', number)
    else:
        raise ValueError("Число не помещается в 2 байта")


def decode_number(in_bytes):
    """
    Декодирует целое число из 2 байтового представления in_bytes

    :param in_bytes: объект bytes, содержащий число
    :return: число, содержащийся в in_bytes
    """

    return struct.unpack('!H', in_bytes)[0]


class Header:
    """
    Класс для заголовка DNS сообщения
    """
    def __init__(self, identifier, message_type, question_count,
                 query_type=QueryType.STANDARD,
                 is_authority_answer=False,
                 is_truncated=False,
                 is_recursion_desired=False,
                 is_recursion_available=False,
                 response_type=ResponseType.NO_ERROR,
                 answer_count=0, authority_count=0, additional_count=0):
        """
        Инициализирует Header

        :param int identifier: уникальный идентификатор
        :param MessageType message_type: тип сообщения
        :param int question_count: количество разделов с вопросами
        :param query_type: тип запроса
        :param bool is_authority_answer: является ли ответ авторитетным
        :param bool is_truncated: разделено ли сообщение на несколько частей
        :param bool is_recursion_desired: требуется ли рекурсия
        :param bool is_recursion_available: доступна ли рекурсия на сервере
        :param ResponseType response_type: тип ответа
        :param int answer_count: кол-во разделов с ответами
        :param int authority_count: кол-во разделов с авторитетными ответами
        :param int additional_count: кол-во разделов с доп. информацией
        """
        self.identifier = identifier
        self.message_type = message_type
        self.query_type = query_type
        self.is_authority_answer = is_authority_answer
        self.is_truncated = is_truncated
        self.is_recursion_desired = is_recursion_desired
        self.is_recursion_available = is_recursion_available
        self.response_type = response_type
        self.question_count = question_count
        self.answer_count = answer_count
        self.authority_count = authority_count
        self.additional_count = additional_count

    def _encode_flags(self):
        """
        Кодирует флаги Header'а сообщения в байты
        :return: объект bytes содержащий флаги
        """
        flags = self.message_type.value

        flags <<= 4
        flags |= self.query_type.value

        flags <<= 1
        flags |= self.is_authority_answer

        flags <<= 1
        flags |= self.is_truncated

        flags <<= 1
        flags |= self.is_recursion_desired

        flags <<= 1
        flags |= self.is_recursion_available

        flags <<= 3

        flags <<= 4
        flags |= self.response_type.value

        return encode_number(flags)

    def to_bytes(self):
        """
        Кодирует Header сообщения в байты
        :return: объект bytes содержащий Header
        """
        encoded = encode_number(self.identifier)
        encoded += self._encode_flags()
        encoded += encode_number(self.question_count)
        encoded += encode_number(self.answer_count)
        encoded += encode_number(self.authority_count)
        encoded += encode_number(self.additional_count)

        return encoded

    @staticmethod
    def from_bytes(in_bytes, beginning):
        """
        Создаёт Header из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала Header внутри Query/Answer
        :return: объект namedtuple, содержащий Header и offset
        """
        offset = beginning

        identifier_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        identifier = decode_number(identifier_in_bytes)

        flags_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        flags = int.from_bytes(flags_in_bytes, byteorder='big')

        response_type = ResponseType(flags & 15)
        flags >>= 4

        flags >>= 3

        is_recursion_available = bool(flags & 1)
        flags >>= 1

        is_recursion_desired = bool(flags & 1)
        flags >>= 1

        is_truncated = bool(flags & 1)
        flags >>= 1

        is_authority_answer = bool(flags & 1)
        flags >>= 1

        query_type = QueryType(flags & 15)
        flags >>= 4

        message_type = MessageType(flags & 1)

        qcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        qcount = decode_number(qcount_in_bytes)

        anscount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        anscount = decode_number(anscount_in_bytes)

        authcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        authcount = decode_number(authcount_in_bytes)

        addcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        addcount = decode_number(addcount_in_bytes)

        header_wrapper = namedtuple('Header', ['header', 'offset'])

        header = Header(identifier, message_type, qcount,
                        query_type=query_type,
                        is_authority_answer=is_authority_answer,
                        is_truncated=is_truncated,
                        is_recursion_desired=is_recursion_desired,
                        is_recursion_available=is_recursion_available,
                        response_type=response_type,
                        answer_count=anscount, authority_count=authcount,
                        additional_count=addcount)

        return header_wrapper(header, offset)
