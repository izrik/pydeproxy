

class Handling:
    """
    An object representing a request received by an endpoint and the
    response it returns.
    """
    def __init__(self, endpoint, request, response):
        self.endpoint = endpoint
        self.request = request
        self.response = response

    def __repr__(self):
        return ('Handling(endpoint=%r, request=%r, response=%r)' %
                (self.endpoint, self.request, self.response))
