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
        Кодирует флаги заголовка сообщения в байты
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
        encoded = encode_number(self.identifier)
        encoded += self._encode_flags()
        encoded += encode_number(self.question_count)
        encoded += encode_number(self.answer_count)
        encoded += encode_number(self.authority_count)
        encoded += encode_number(self.additional_count)

        return encoded
