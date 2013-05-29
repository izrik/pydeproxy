
from .header_collection import HeaderCollection

class Request:
    """A simple HTTP Request, with method, path, headers, and body."""
    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = HeaderCollection(headers)
        self.body = body

    def __repr__(self):
        return ('Request(method=%r, path=%r, headers=%r, body=%r)' %
                (self.method, self.path, self.headers, self.body))
