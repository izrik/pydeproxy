
from .header_collection import HeaderCollection

class Response:
    """A simple HTTP Response, with status code, status message, headers, and
    body."""
    def __init__(self, code, message, headers, body):
        self.code = code
        self.message = message
        self.headers = HeaderCollection(headers)
        self.body = body

    def __repr__(self):
        return ('Response(code=%r, message=%r, headers=%r, body=%r)' %
                (self.code, self.message, self.headers, self.body))
