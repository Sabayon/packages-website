from entropy.exceptions import EntropyException

class EntropyServicesError(EntropyException):
    """ Generic Entropy Services exception. All classes here belong to this. """

class ServiceConnectionError(EntropyServicesError):
    """Cannot connect to service"""

class TransactionError(Exception):
    """ Error during transaction """

    def __init__(self, code, message):
        self.code = code
        self.message = message
