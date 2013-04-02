
import threading


class MessageChain:
    """
    An object containing the initial request sent via the make_request method,
    together with all request/response pairs (Handling objects) processed by
    DeproxyEndpoint objects.
    """
    def __init__(self, handler_function):
        self.sent_request = None
        self.received_response = None
        self.handler_function = handler_function
        self.handlings = []
        self.orphaned_handlings = []
        self.lock = threading.Lock()

    def add_handling(self, handling):
        with self.lock:
            self.handlings.append(handling)

    def add_orphaned_handling(self, handling):
        with self.lock:
            self.orphaned_handlings.append(handling)

    def __repr__(self):
        return ('MessageChain(handler_function=%r, sent_request=%r, '
                'handlings=%r, received_response=%r)' %
                (self.handler_function, self.sent_request, self.handlings,
                 self.received_response))
