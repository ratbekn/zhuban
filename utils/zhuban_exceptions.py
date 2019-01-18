class DNSClientException(Exception):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Внутренняя ошибка программы")


class InvalidServerResponse(DNSClientException):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Неправильный ответ от сервера")


class InvalidAnswer(DNSClientException):  # pragma: no cover
    def __init__(self):
        Exception.__init__(self, "Невалидные данные для создания Answer")
