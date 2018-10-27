import random
import struct
from collections import namedtuple
from .dns_enums import (
    MessageType, QueryType, ResponseType, ResourceRecordType,
    ResourceRecordClass
)
from utils.zhuban_exceptions import (
    InvalidAnswer
)


_MAX_DOUBLE_BYTE_NUMBER = 65535


def _encode_number(number):
    """
    Кодирует целое число в 2 байта с порядком байт big-endian

    :param int number: целое число, которое нужно закодировать
    :raise ValueError: если число не поместиться в 2 байта
    :return: объект bytes содержащий число
    """
    if 0 <= number < _MAX_DOUBLE_BYTE_NUMBER:
        return struct.pack('!H', number)

    raise ValueError("Число не помещается в 2 байта")


def _decode_number(in_bytes):
    """
    Декодирует целое число из 2 байтового представления in_bytes

    :param in_bytes: объект bytes, содержащий число
    :return: число, содержащийся в in_bytes
    """

    return struct.unpack('!H', in_bytes)[0]


def _encode_name(string):
    """
    Кодирует строку в байты в формате предназначенном для DNS

    :param string: строка для кодирования
    :return: объект bytes содержащий строку
    """
    domains = string.split('.')
    domains_in_bytes = []
    for d in domains:
        domains_in_bytes.append(struct.pack('!B', len(d)))
        domains_in_bytes.append(d.encode())

    domains_in_bytes.append(b'\x00')

    return b''.join(domains_in_bytes)


def _decode_name(in_bytes, offset):
    """
    Декодирует доменное имя из байтов, содержащих DNS сообщение

    :param bytes in_bytes: объект bytes содержащий Query/Answer
    :param int offset: индекс первого байта строки в in_bytes
    :return: namedtuple { декодированное имя, offset }
    """
    index = offset
    offset = 0
    decoded_tokens = []
    while in_bytes[index]:
        current_byte = in_bytes[index]
        if current_byte >> 6 == 3:
            if offset == 0:
                offset = index + 2
            index = _decode_number(in_bytes[index:index + 2]) ^ (3 << 14)
        else:
            decoded_tokens.append(
                in_bytes[index + 1:index + 1 + current_byte].decode('utf-8'))
            index += current_byte + 1
    if offset == 0:
        offset = index + 1

    decoded = '.'.join(decoded_tokens)

    string_wrapper = namedtuple('decoded_name', ['decoded_', 'offset'])

    return string_wrapper(decoded, offset)


def _get_identifier():
    """
    Возвращает рандомный идентификатор
    :return: двубайтовое число
    """
    return random.randint(0, 65535)


class Query:
    """
    Класс для представления DNS-запроса
    """
    def __init__(self, hostname, rr_type=ResourceRecordType.A,
                 is_recursion_desired=True, qtype=QueryType.STANDARD):
        """
        Инициализирует Query

        :param hostname: доменное имя требуемой DNS записи
        :param rr_type: тип запрашиваемой DNS записи
        :param is_recursion_desired: требуется ли рекурсия
        """
        self.header = _Header(
            _get_identifier(), MessageType.QUERY, 1, qtype,
            is_recursion_desired=is_recursion_desired)

        self.question = _Question(hostname, rr_type)

    def to_bytes(self):
        """
        Кодирует Query в байты

        :return: объект bytes содержащий Query
        """

        return self.header.to_bytes() + self.question.to_bytes()


class Answer:
    """
    Класс для представления ответа от DNS-сервера
    """
    def __init__(self, header, questions, answers, authorities, additions):
        """
        Инициализирует Answer

        :param _Header header: заголовок DNS-ответа
        :param list of _Question questions: DNS вопросы
        :param list of _ResourceRecord answers: DNS ответы
        :param list of _ResourceRecord authorities: авторитетные сервера
        :param list of _ResourceRecord additions: дополнительная информация
        """
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additions = additions

    @classmethod
    def from_bytes(cls, in_bytes):
        """
        Создаёт Answer из объекта bytes, содержащего Answer

        :param bytes in_bytes: объект bytes, содержащий Answer
        :return: объект Answer, декодированный из in_bytes
        """
        try:
            header, offset = _Header.from_bytes(in_bytes, 0)
            questions = []
            for _ in range(header.question_count):
                question, offset = _Question.from_bytes(in_bytes, offset)
                questions.append(question)

            answers = []
            for _ in range(header.answer_count):
                answer, offset = _ResourceRecord.from_bytes(in_bytes, offset)
                answers.append(answer)

            authorities = []
            for _ in range(header.authority_count):
                authority, offset = _ResourceRecord.from_bytes(
                    in_bytes, offset)
                authorities.append(authority)

            additions = []
            for _ in range(header.additional_count):
                additional, offset = _ResourceRecord.from_bytes(
                    in_bytes, offset)
                additions.append(additional)
        except Exception as e:
            raise InvalidAnswer from e

        return cls(header, questions, answers, authorities, additions)


class _Header:
    """
    Класс для заголовка DNS сообщения
    """
    def __init__(
            self, identifier, message_type, question_count,
            query_type=QueryType.STANDARD, is_authority_answer=False,
            is_truncated=False, is_recursion_desired=False,
            is_recursion_available=False, response_type=ResponseType.NO_ERROR,
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
        Кодирует флаги Header'а в байты

        :return: объект bytes содержащий флаги
        """

        flags = (
            (self.message_type.value << 15)
            | (self.query_type.value << 11)
            | (self.is_authority_answer << 10)
            | (self.is_truncated << 9)
            | (self.is_recursion_desired << 8)
            | (self.is_recursion_available << 7)
            | (0 << 3)
            | (self.response_type << 0)
        )

        return _encode_number(flags)

    def to_bytes(self):
        """
        Кодирует Header в байты

        :return: объект bytes содержащий Header
        """
        encoded_tokens = [
            _encode_number(self.identifier),
            self._encode_flags(),
            _encode_number(self.question_count),
            _encode_number(self.answer_count),
            _encode_number(self.authority_count),
            _encode_number(self.additional_count)
        ]

        return b''.join(encoded_tokens)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт Header из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала Header внутри Query/Answer
        :return: объект namedtuple, содержащий Header и offset
        """
        offset = beginning

        identifier_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        identifier = _decode_number(identifier_in_bytes)

        flags_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        flags = int.from_bytes(flags_in_bytes, byteorder='big')

        response_type = ResponseType(flags & 15)

        is_recursion_available = bool(flags & 0x80)

        is_recursion_desired = bool(flags & 0x100)

        is_truncated = bool(flags & 0x200)

        is_authority_answer = bool(flags & 0x400)

        flags >>= 11
        query_type = QueryType(flags & 15)
        flags >>= 4

        message_type = MessageType(flags & 1)

        qcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        qcount = _decode_number(qcount_in_bytes)

        anscount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        anscount = _decode_number(anscount_in_bytes)

        authcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        authcount = _decode_number(authcount_in_bytes)

        addcount_in_bytes = in_bytes[offset:offset + 2]
        offset += 2
        addcount = _decode_number(addcount_in_bytes)

        header_wrapper = namedtuple('Header', ['header', 'offset'])

        header = cls(
            identifier, message_type, qcount, query_type=query_type,
            is_authority_answer=is_authority_answer, is_truncated=is_truncated,
            is_recursion_desired=is_recursion_desired,
            is_recursion_available=is_recursion_available,
            response_type=response_type, answer_count=anscount,
            authority_count=authcount, additional_count=addcount)

        return header_wrapper(header, offset)


class _Question:
    """
    Класс для вопроса DNS сообщения
    """
    def __init__(self, name, type_=ResourceRecordType.A):
        """
        Инициализирует Question

        :param name: доменное имя
        :param type_: тип запрашиваемой dns записи
        """
        self.name = name
        self.type_ = type_
        self.class_ = ResourceRecordClass.IN

    def to_bytes(self):
        """
        Кодирует Question сообщения в байты

        :return: объект bytes содержащий Question
        """
        encoded_tokens = [
            _encode_name(self.name),
            _encode_number(self.type_.value),
            _encode_number(self.class_.value)
        ]

        return b''.join(encoded_tokens)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт Question из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала Question внутри Query/Answer
        :return: объект namedtuple, содержащий Question и offset
        """
        name, offset = _decode_name(in_bytes, beginning)
        type_ = _decode_number(in_bytes[offset:offset + 2])
        offset += (2 + 2)

        question_wrapper = namedtuple(
            'question_wrapper', ['question', 'offset'])

        return question_wrapper(cls(name, type_=type_), offset)


class _AResourceData:
    """
    Класс для данных DNS записи типа A
    """
    def __init__(self, in_bytes):
        """
        Инициализирует AResourceData

        :param bytes in_bytes: 4 байта, содержащие ip address
        """
        ip = struct.unpack('BBBB', in_bytes)
        self.ip = '.'.join(map(str, ip))


class _PTRResourceData:
    """
    Класс для данных DNS записи типа PTR
    """
    def __init__(self, in_bytes):
        """
        Инициализирует PTRResourceData
        :param in_bytes: байты содержащие domain_name
        """
        self.name = _decode_name(in_bytes, 0).decoded_


class _ResourceRecord:
    """
    Класс для ResourceRecord
    """
    def __init__(
            self, name, type_, length, data, ttl=0,
            class_=ResourceRecordClass.IN):
        """
        Инициализирует ResourceRecord

        :param str name: запрошенное доменное имя
        :param ResourceRecordType type_: тип DNS записи
        :param int length: длина данных
        :param data: данные
        :param ttl: время в секундах, сколько запись может быть в кэширована
        :param ResourceRecordClass class_: класс ResourceRecord
        """
        self.name = name
        self.type_ = type_
        self.class_ = class_
        self.ttl = ttl
        self.length = length
        self.data = data

    @classmethod
    def _decode_data(cls, in_bytes, type_, length, offset):
        """
        Декодирует данные ResourceRecord

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param ResourceRecordType type_: тип DNS записи
        :param int length: длина данных в байтах
        :param int offset: индекс первого байта данных в in_bytes
        :return: соответствующий type_ *ResourceData
        """
        data_in_bytes = in_bytes[offset:offset + length]
        if type_ == ResourceRecordType.A:
            return _AResourceData(data_in_bytes)
        elif type_ == ResourceRecordType.PTR:
            return _PTRResourceData(data_in_bytes)

    @classmethod
    def from_bytes(cls, in_bytes, beginning):
        """
        Создаёт ResourceRecord из объекта bytes, содержащего Query/Answer

        :param bytes in_bytes: объект bytes, содержащий Query/Answer
        :param int beginning: индекс начала ResourceRecord внутри Query/Answer
        :return: объект namedtuple, содержащий ResourceRecord и offset
        """
        name, offset = _decode_name(in_bytes, beginning)

        type_ = _decode_number(in_bytes[offset:offset + 2])
        offset += 2

        class_ = _decode_number(in_bytes[offset:offset + 2])
        offset += 2

        ttl = struct.unpack('!I', in_bytes[offset:offset + 4])[0]
        offset += 4

        length = _decode_number(in_bytes[offset:offset + 2])
        offset += 2

        data = _ResourceRecord._decode_data(in_bytes, type_, length, offset)
        offset += length

        rr_wrapper = namedtuple('rr_wrapper', ['resource_record', 'offset'])

        return rr_wrapper(cls(name, type_, length, data, ttl, class_), offset)
