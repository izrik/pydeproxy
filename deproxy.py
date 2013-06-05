#!/usr/bin/env python

import threading
import socket
import time
import collections
import uuid
import select
import sys
import mimetools
import urlparse
import inspect
import logging
import ssl


__version_info__ = (0, 8)
__version__ = '.'.join(map(str, __version_info__))


# The Python system version, truncated to its first component.
python_version = "Python/" + sys.version.split()[0]

# The server software version.
# The format is multiple whitespace-separated strings,
# where each string is of the form name[/version].
deproxy_version = "Deproxy/%s" % __version__

version_string = deproxy_version + ' ' + python_version


logger = logging.getLogger(__name__)

request_id_header_name = 'Deproxy-Request-ID'


class HeaderCollection(object):
    """
    A collection class for HTTP Headers. This class combines aspects of a list
    and a dict. Lookup is always case-insenitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self, mapping=None, **kwargs):
        self.headers = []
        if mapping is not None:
            for k, v in mapping.iteritems():
                self.add(k, v)
        if kwargs is not None:
            for k, v in kwargs.iteritems():
                self.add(k, v)

    def __contains__(self, item):
        item = item.lower()
        for header in self.headers:
            if header[0].lower() == item:
                return True
        return False

    def __len__(self):
        return self.headers.__len__()

    def __getitem__(self, key):
        key = key.lower()
        for header in self.headers:
            if header[0].lower() == key:
                return header[1]

    def __setitem__(self, key, value):
        lower = key.lower()
        for i, header in enumerate(self.headers):
            if header[0].lower() == lower:
                headers[i] = (header[0], value)
                return
        else:
            self.add(key, value)

    def __delitem__(self, key):
        self.delete_all(name=key)

    def __iter__(self):
        return self.iterkeys()

    def add(self, name, value):
        self.headers.append((name, value,))

    def find_all(self, name):
        name = name.lower()
        for header in self.headers:
            if header[0].lower() == name:
                yield header[1]

    def delete_all(self, name):
        lower = name.lower()
        self.headers = [header for header in self.headers
                        if header[0].lower() != lower]

    def iterkeys(self):
        for header in self.headers:
            yield header[0]

    def itervalues(self):
        for header in self.headers:
            yield header[1]

    def iteritems(self):
        for header in self.headers:
            yield header

    def keys(self):
        return [key for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def clear(self):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError

    @classmethod
    def from_keys(cls, seq, value=None):
        raise NotImplementedError

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    def has_key(self, key):
        raise NotImplementedError

    def pop(self, key, default=None):
        raise NotImplementedError

    def popitem(self):
        raise NotImplementedError

    def setdefault(self, key, default=None):
        raise NotImplementedError

    def update(self, other=None, **kwargs):
        raise NotImplementedError

    def viewitems(self):
        raise NotImplementedError

    def viewkeys(self):
        raise NotImplementedError

    def viewvalues(self):
        raise NotImplementedError

    @staticmethod
    def from_stream(rfile):
        headers = HeaderCollection()
        line = rfile.readline()
        while line and line != '\x0d\x0a':
            name, value = line.split(':', 1)
            name = name.strip()
            line = rfile.readline()
            while line.startswith(' ') or line.startswith('\t'):
                # Continuation lines - see RFC 2616, section 4.2
                value += ' ' + line
                line = rfile.readline()
            headers.add(name, value.strip())
        return headers

    def __str__(self):
        return self.headers.__str__()

    def __repr__(self):
        return self.headers.__repr__()


class Response:
    """A simple HTTP Response, with status code, status message, headers, and
    body."""
    def __init__(self, code, message=None, headers=None, body=None):
        """
        Parameters:

        code - A numerical status code. This doesn't have to be a valid HTTP
            status code; 600+ values are acceptable also.
        message - An optional message to go along with the status code. If
            None, a suitable default will be provided based on the given status
            .code If ``code`` is not a valid HTTP status code, then the default
            is the empty string.
        headers - An optional collection of name/value pairs, either a mapping
            object like ``dict``, or a HeaderCollection. Defaults to an empty
            collection.
        body - An optional response body. Defaults to the empty string.
        """

        if message is None:
            if code in message_by_response_code:
                message = message_by_response_code[code]
            elif int(code) in message_by_response_code:
                message = message_by_response_code[int(code)]
            else:
                message = ''

        if headers is None:
            headers = {}

        if body is None:
            body = ''

        self.code = str(code)
        self.message = str(message)
        self.headers = HeaderCollection(headers)
        self.body = str(body)

    def __repr__(self):
        return ('Response(code=%r, message=%r, headers=%r, body=%r)' %
                (self.code, self.message, self.headers, self.body))


class Request:
    """A simple HTTP Request, with method, path, headers, and body."""
    def __init__(self, method, path, headers=None, body=None):
        """
        Parameters:

        method - The HTTP method to use, such as 'GET', 'POST', or 'PUT'.
        path - The relative path of the resource requested.
        headers - An optional collection of name/value pairs, either a mapping
            object like ``dict``, or a HeaderCollection. Defaults to an empty
            collection.
        body - An optional request body. Defaults to the empty string.
        """

        if headers is None:
            headers = {}

        if body is None:
            body = ''

        self.method = str(method)
        self.path = str(path)
        self.headers = HeaderCollection(headers)
        self.body = str(body)

    def __repr__(self):
        return ('Request(method=%r, path=%r, headers=%r, body=%r)' %
                (self.method, self.path, self.headers, self.body))


def simple_handler(request):
    """
    Handler function.
    Returns a 200 OK Response, with no additional headers or response body.
    """
    logger.debug('')
    return Response(200, 'OK', {}, '')


def echo_handler(request):
    """
    Handler function.
    Returns a 200 OK Response, with the same headers and body as the request.
    """
    logger.debug('')
    return Response(200, 'OK', request.headers, request.body)


def delay(timeout, next_handler=simple_handler):
    """
    Factory function.
    Returns a handler that delays the request for the specified number of
    seconds, forwards it to the next handler function, and returns that
    handler function's Response.

    Parameters:

    timeout - The amount of time, in seconds, to delay before passing the
        request on to the next handler.
    next_handler - The next handler to process the request after the delay.
        Defaults to ``simple_handler``.
    """
    def delayer(request):
        logger.debug('delaying for %i seconds' % timeout)
        time.sleep(timeout)
        return next_handler(request)

    delayer.__doc__ = ('Delay for %s seconds, then forward the Request to the '
                       'next handler' % str(timeout))

    return delayer


def route(scheme, host, deproxy):
    """
    Factory function.
    Returns a handler that forwards the request to a specified URL, using
    either HTTP or HTTPS (regardless of what protocol was used in the initial
    request), and returning the response from the host so routed to.
    """
    logger.debug('')

    def route_to_host(request):
        logger.debug('scheme, host = %s, %s' % (scheme, host))
        logger.debug('request = %s %s' % (request.method, request.path))

        request2 = Request(request.method, request.path, request.headers,
                           request.body)

        if 'Host' in request2.headers:
            request2.headers.delete_all('Host')
        request2.headers.add('Host', host)

        logger.debug('sending request')
        response = deproxy.send_request(scheme, host, request2)
        logger.debug('received response')

        return response, False

    route_to_host.__doc__ = "Route responses to %s using %s" % (host, scheme)

    return route_to_host


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


class MessageChain:
    """
    An object containing the initial request sent via the make_request method,
    and all request/response pairs (Handling objects) processed by
    DeproxyEndpoint objects.
    """
    def __init__(self, default_handler, handlers):
        """
        Params:
        default_handler - An optional handler function to use for requests
            related to this MessageChain, if not specified elsewhere
        handlers - A mapping object that maps endpoint references or names of
            endpoints to handlers
        """
        self.sent_request = None
        self.received_response = None
        self.default_handler = default_handler
        self.handlers = handlers
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
        return ('MessageChain(default_handler=%r, handlers=%r, '
                'sent_request=%r, handlings=%r, received_response=%r, '
                'orphaned_handlings=%r)' %
                (self.default_handler, self.handlers, self.sent_request,
                 self.handlings, self.received_response,
                 self.orphaned_handlings))


def read_body_from_stream(stream, headers):
    if ('Transfer-Encoding' in headers and
            headers['Transfer-Encoding'] != 'identity'):
        # 2
        logger.debug('NotImplementedError - Transfer-Encoding != identity')
        raise NotImplementedError
    elif 'Content-Length' in headers:
        # 3
        length = int(headers['Content-Length'])
        body = stream.read(length)
    elif False:
        # multipart/byteranges ?
        logger.debug('NotImplementedError - multipart/byteranges')
        raise NotImplementedError
    else:
        # there is no body
        body = None
    return body


class Deproxy:
    """The main class."""

    def __init__(self, default_handler=None):
        """
        Params:
        default_handler - An optional handler function to use for requests, if
            not specified elsewhere
        """
        self._message_chains_lock = threading.Lock()
        self._message_chains = dict()
        self._endpoint_lock = threading.Lock()
        self._endpoints = []
        self.default_handler = default_handler

    def make_request(self, url, method='GET', headers=None, request_body='',
                     default_handler=None, handlers=None,
                     add_default_headers=True):
        """
        Make an HTTP request to the given url and return a MessageChain.

        Parameters:

        url - The URL to send the client request to
        method - The HTTP method to use, default is 'GET'
        headers - A collection of request headers to send, defaults to None
        request_body - The body of the request, as a string, defaults to empty
            string
        default_handler - An optional handler function to use for requests
            related to this client request
        handlers - A mapping object that maps endpoint references or names of
            endpoints to handlers. If an endpoint or its name is a key within
            ``handlers``, all requests to that endpoint will be handled by the
            associated handler
        add_default_headers - If true, the 'Host', 'Accept', 'Accept-Encoding',
            and 'User-Agent' headers will be added to the list of headers sent,
            if not already specified in the ``headers`` parameter above.
            Otherwise, those headers are not added. Defaults to True.
        """
        logger.debug('')

        if headers is None:
            headers = HeaderCollection()
        else:
            headers = HeaderCollection(headers)

        request_id = str(uuid.uuid4())
        if request_id_header_name not in headers:
            headers.add(request_id_header_name, request_id)

        message_chain = MessageChain(default_handler=default_handler,
                                     handlers=handlers)
        self.add_message_chain(request_id, message_chain)

        urlparts = list(urlparse.urlsplit(url, 'http'))
        scheme = urlparts[0]
        host = urlparts[1]
        urlparts[0] = ''
        urlparts[1] = ''
        path = urlparse.urlunsplit(urlparts)

        logger.debug('request_body: "{0}"'.format(request_body))
        if len(request_body) > 0:
            headers.add('Content-Length', len(request_body))

        if add_default_headers:
            if 'Host' not in headers:
                headers.add('Host', host)
            if 'Accept' not in headers:
                headers.add('Accept', '*/*')
            if 'Accept-Encoding' not in headers:
                headers.add('Accept-Encoding',
                            'identity, deflate, compress, gzip')
            if 'User-Agent' not in headers:
                headers.add('User-Agent', version_string)

        request = Request(method, path, headers, request_body)

        response = self.send_request(scheme, host, request)

        self.remove_message_chain(request_id)

        message_chain.sent_request = request
        message_chain.received_response = response

        return message_chain

    def create_ssl_connection(self, address,
                              timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                              source_address=None):
        """
        Copied from the socket module and modified for ssl support.

        Connect to *address* and return the socket object.

        Convenience function.  Connect to *address* (a 2-tuple ``(host,
        port)``) and return the socket object.  Passing the optional
        *timeout* parameter will set the timeout on the socket instance
        before attempting to connect.  If no *timeout* is supplied, the
        global default timeout setting returned by :func:`getdefaulttimeout`
        is used.  If *source_address* is set it must be a tuple of (host, port)
        for the socket to bind as a source address before making the
        connection. A host of '' or port 0 tells the OS to use the default.
        """

        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)

                sock = ssl.wrap_socket(sock)

                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise error("getaddrinfo returns an empty list")

    def send_request(self, scheme, host, request):
        """Send the given request to the host and return the Response."""
        logger.debug('sending request (scheme="%s", host="%s")' %
                     (scheme, host))
        hostparts = host.split(':')
        if len(hostparts) > 1:
            port = hostparts[1]
        else:
            if scheme == 'https':
                port = 443
            else:
                port = 80
        hostname = hostparts[0]
        hostip = socket.gethostbyname(hostname)

        request_line = '%s %s HTTP/1.1\r\n' % (request.method, request.path)
        lines = [request_line]

        for name, value in request.headers.iteritems():
            lines.append('%s: %s\r\n' % (name, value))
        lines.append('\r\n')
        if request.body is not None and len(request.body) > 0:
            lines.append(request.body)

        #for line in lines:
        #    logger.debug('  ' + line)

        logger.debug('Creating connection (hostname="%s", port="%s")' %
                     (hostname, str(port)))

        address = (hostname, port)
        if scheme == 'https':
            s = self.create_ssl_connection(address)
        else:
            s = socket.create_connection(address)

        s.send(''.join(lines))

        rfile = s.makefile('rb', -1)

        logger.debug('Reading response line')
        response_line = rfile.readline(65537)
        if (len(response_line) > 65536):
            raise ValueError
        response_line = response_line.rstrip('\r\n')
        logger.debug('Response line is ok: %s' % response_line)

        words = response_line.split()

        proto = words[0]
        code = words[1]
        message = ' '.join(words[2:])

        logger.debug('Reading headers')
        response_headers = HeaderCollection.from_stream(rfile)
        logger.debug('Headers ok')
        for k,v in response_headers.iteritems():
            logger.debug('  %s: %s', k, v)

        logger.debug('Reading body')
        body = read_body_from_stream(rfile, response_headers)

        logger.debug('Creating Response object')
        response = Response(code, message, response_headers, body)

        logger.debug('Returning Response object')
        return response

    def add_endpoint(self, port, name=None, hostname=None,
                     default_handler=None):
        """Add a DeproxyEndpoint object to this Deproxy object's list of
        endpoints, giving it the specified server address, and then return the
        endpoint.

        Params:
        port - The port on which the new endpoint will listen
        name - An optional descriptive name for the new endpoint. If None, a
            suitable default will be generated
        hostname - The ``hostname`` portion of the address tuple passed to
            ``socket.bind``. If not specified, it defaults to 'localhost'
        default_handler - An optional handler function to use for requests that
            the new endpoint will handle, if not specified elsewhere
        """

        logger.debug('')
        endpoint = None
        with self._endpoint_lock:
            if name is None:
                name = 'Endpoint-%i' % len(self._endpoints)
            endpoint = DeproxyEndpoint(self, port=port, name=name,
                                       hostname=hostname,
                                       default_handler=default_handler)
            self._endpoints.append(endpoint)
            return endpoint

    def _remove_endpoint(self, endpoint):
        """Remove a DeproxyEndpoint from the list of endpoints. Returns True if
        the endpoint was removed, or False if the endpoint was not in the list.
        This method should normally not be called by user code. Instead, call
        the endpoint's shutdown method."""
        logger.debug('')
        with self._endpoint_lock:
            count = len(self._endpoints)
            self._endpoints = [e for e in self._endpoints if e != endpoint]
            return (count != len(self._endpoints))

    def shutdown_all_endpoints(self):
        """Shutdown and remove all endpoints in use."""
        logger.debug('')
        endpoints = []
        with self._endpoint_lock:
            endpoints = list(self._endpoints)
        # be sure we're not holding the lock when shutdown calls
        # _remove_endpoint.
        for e in endpoints:
            e.shutdown()

    def add_message_chain(self, request_id, message_chain):
        """Add a MessageChain to the internal list for the given request ID."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            self._message_chains[request_id] = message_chain

    def remove_message_chain(self, request_id):
        """Remove a particular MessageChain from the internal list."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            del self._message_chains[request_id]

    def get_message_chain(self, request_id):
        """Return the MessageChain for the given request ID."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            if request_id in self._message_chains:
                return self._message_chains[request_id]
            else:
                #logger.debug('no message chain found for request_id %s' %
                # request_id)
                #for rid, mc in self._message_chains.iteritems():
                #    logger.debug('  %s - %s' % (rid, mc))
                return None

    def add_orphaned_handling(self, handling):
        """Add the handling to all available MessageChains."""
        logger.debug('Adding orphaned handling')
        with self._message_chains_lock:
            for mc in self._message_chains.itervalues():
                mc.add_orphaned_handling(handling)


class DeproxyEndpoint:

    """A class that acts as a mock HTTP server."""

    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    request_queue_size = 5
    _conn_number = 1
    _conn_number_lock = threading.Lock()

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    # Most web servers default to HTTP 0.9, i.e. don't send a status line.
    default_request_version = "HTTP/0.9"

    # The version of the HTTP protocol we support.
    # Set this to HTTP/1.1 to enable automatic keepalive
    protocol_version = "HTTP/1.1"

    # Disable nagle algoritm for this socket, if True.
    # Use only when wbufsize != 0, to avoid small packets.
    disable_nagle_algorithm = False

    def __init__(self, deproxy, port, name, hostname=None,
                 default_handler=None):
        """
        Initialize a DeproxyEndpoint

        Params:
        deproxy - The parent Deproxy object that contains this endpoint
        port - The port on which this endpoint will listen
        name - A descriptive name for this endpoint
        hostname - The ``hostname`` portion of the address tuple passed to
            ``socket.bind``. If not specified, it defaults to 'localhost'
        default_handler - An optional handler function to use for requests that
            this endpoint services, if not specified elsewhere
        """

        logger.debug('port=%s, name=%s, hostname=%s', port, name, hostname)

        if hostname is None:
            hostname = 'localhost'

        self.deproxy = deproxy
        self.name = name
        self.port = port
        self.hostname = hostname
        self.default_handler = default_handler

        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False

        self.socket = socket.socket(self.address_family,
                                    self.socket_type)

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((hostname, port))
        self.socket_address = self.socket.getsockname()

        self.fqdn = socket.getfqdn(self.socket_address[0])

        self.socket.listen(self.request_queue_size)

        thread_name = 'Thread-%s' % self.name
        self.server_thread = threading.Thread(target=self.serve_forever,
                                              name=thread_name)
        self.server_thread.daemon = True
        self.server_thread.start()

    def process_new_connection(self, request, client_address):
        logger.debug('received request from %s' % str(client_address))
        try:
            connection = request
            if self.disable_nagle_algorithm:
                connection.setsockopt(socket.IPPROTO_TCP,
                                      socket.TCP_NODELAY, True)
            rfile = connection.makefile('rb', -1)
            wfile = connection.makefile('wb', 0)

            try:
                close = self.handle_one_request(rfile, wfile)
                while not close:
                    close = self.handle_one_request(rfile, wfile)
            finally:
                if not wfile.closed:
                    wfile.flush()
                wfile.close()
                rfile.close()
        except:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def shutdown_request(self, request):
        """Called to shutdown and close an individual request."""
        logger.debug('')
        try:
            #explicitly shutdown.  socket.close() merely releases
            #the socket and waits for GC to perform the actual close.
            request.shutdown(socket.SHUT_WR)
        except socket.error:
            pass  # some platforms may raise ENOTCONN here
        request.close()

    def serve_forever(self, poll_interval=0.5):
        """Handle one request at a time until shutdown.

        Polls for shutdown every poll_interval seconds. Ignores
        self.timeout. If you need to do periodic tasks, do them in
        another thread.
        """
        logger.debug('')
        self.__is_shut_down.clear()
        try:
            while not self.__shutdown_request:
                # XXX: Consider using another file descriptor or
                # connecting to the socket to wake this up instead of
                # polling. Polling reduces our responsiveness to a
                # shutdown request and wastes cpu at all other times.
                r, w, e = select.select([self.socket], [], [], poll_interval)
                if self.socket in r:
                    try:
                        request, client_address = self.socket.accept()
                    except socket.error:
                        return

                    try:
                        with self._conn_number_lock:
                            t = threading.Thread(
                                target=self.process_new_connection,
                                name=("Thread - Connection %i on %s" %
                                      (self._conn_number, self.name)),
                                args=(request, client_address))
                            self._conn_number += 1
                        t.daemon = True
                        t.start()

                    except:
                        self.handle_error(request, client_address)
                        self.shutdown_request(request)

        finally:
            self.socket.close()
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def shutdown(self):
        """Stops the serve_forever loop.

        Blocks until the loop has finished. This must be called while
        serve_forever() is running in another thread, or it will
        deadlock.
        """
        logger.debug('Shutting down "%s"' % self.name)
        self.deproxy._remove_endpoint(self)
        self.__shutdown_request = True
        self.__is_shut_down.wait()
        self.server_thread.join(timeout=5)
        logger.debug('Finished shutting down "%s"' % self.name)

    def handle_error(self, request, client_address):
        """Handle an error gracefully.  May be overridden.

        The default is to print a traceback and continue.

        """
        logger.debug('')
        print '-' * 40
        print 'Exception happened during processing of request from',
        print client_address
        import traceback
        traceback.print_exc()  # XXX But this goes to stderr!
        print '-' * 40

    def handle_one_request(self, rfile, wfile):
        logger.debug('')
        close_connection = True
        try:
            logger.debug('calling parse_request')
            ret = self.parse_request(rfile, wfile)
            logger.debug('returned from parse_request')
            if not ret:
                return 1

            (incoming_request, persistent_connection) = ret

            if persistent_connection:
                close_connection = False
                conn_value = incoming_request.headers.get('connection')
                if conn_value:
                    if conn_value.lower() == 'close':
                        close_connection = True
            else:
                close_connection = True
            close_connection = True

            message_chain = None
            request_id = incoming_request.headers.get(request_id_header_name)
            if request_id:
                logger.debug('The request has a request id: %s=%s' %
                             (request_id_header_name, request_id))
                message_chain = self.deproxy.get_message_chain(request_id)
            else:
                logger.debug('The request does not have a request id')

            # Handler resolution:
            #  1. Check the handlers mapping specified to ``make_request``
            #    a. By reference
            #    b. By name
            #  2. Check the default_handler specified to ``make_request``
            #  3. Check the default for this endpoint
            #  4. Check the default for the parent Deproxy
            #  5. Fallback to simple_handler
            if (message_chain and message_chain.handlers is not None and
                    self in message_chain.handlers):
                handler = message_chain.handlers[self]
            elif (message_chain and message_chain.handlers is not None and
                  self.name in message_chain.handlers):
                handler = message_chain.handlers[self.name]
            elif message_chain and message_chain.default_handler is not None:
                handler = message_chain.default_handler
            elif self.default_handler is not None:
                handler = self.default_handler
            elif self.deproxy.default_handler is not None:
                handler = self.deproxy.default_handler
            else:
                # last resort
                handler = simple_handler

            logger.debug('calling handler')
            resp = handler(incoming_request)
            logger.debug('returned from handler')

            add_default_headers = True
            if type(resp) == tuple:
                logger.debug('Handler gave back a tuple: %s',
                             (type(resp[0]), resp[1:]))
                if len(resp) > 1:
                    add_default_headers = resp[1]
                resp = resp[0]

            if (resp.body is not None and
                    'Content-Length' not in resp.headers):
                resp.headers.add('Content-Length', len(resp.body))

            if add_default_headers:
                if 'Server' not in resp.headers:
                    resp.headers['Server'] = version_string
                if 'Date' not in resp.headers:
                    resp.headers['Date'] = self.date_time_string()
            else:
                logger.debug('Don\'t add default response headers.')

            found = resp.headers.get(request_id_header_name)
            if not found and request_id is not None:
                resp.headers[request_id_header_name] = request_id

            outgoing_response = resp

            h = Handling(self, incoming_request, outgoing_response)
            if message_chain:
                message_chain.add_handling(h)
            else:
                self.deproxy.add_orphaned_handling(h)

            self.send_response(wfile, resp)

            wfile.flush()

            if persistent_connection and not close_connection:
                conn_value = incoming_request.headers.get('connection')
                if conn_value:
                    if conn_value.lower() == 'close':
                        close_connection = True

        except socket.timeout, e:
            close_connection = True

        return close_connection

    def parse_request(self, rfile, wfile):
        logger.debug('reading request line')
        request_line = rfile.readline(65537)
        if len(request_line) > 65536:
            self.send_error(wfile, 414, None, self.default_request_version)
            return ()
        if not request_line:
            return ()

        request_line = request_line.rstrip('\r\n')
        logger.debug('request line is ok: "%s"' % request_line)

        if request_line[-2:] == '\r\n':
            request_line = request_line[:-2]
        elif request_line[-1:] == '\n':
            request_line = request_line[:-1]
        words = request_line.split()
        if len(words) == 3:
            [method, path, version] = words
            if version[:5] != 'HTTP/':
                self.send_error(wfile, 400, method,
                                self.default_request_version,
                                "Bad request version (%r)" % version)
                return ()
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(wfile, 400, method,
                                self.default_request_version,
                                "Bad request version (%r)" % version)
                return ()
        elif len(words) == 2:
            [method, path] = words
            version = self.default_request_version
            if method != 'GET':
                self.send_error(wfile, 400, method,
                                self.default_request_version,
                                "Bad HTTP/0.9 request type (%r)" % method)
                return ()
        elif not words:
            return ()
        else:
            self.send_error(wfile, 400, None,
                            self.default_request_version,
                            "Bad request syntax (%r)" % request_line)
            return ()

        logger.debug('checking HTTP protocol version')
        if (version != 'HTTP/1.1' and
                version != 'HTTP/1.0' and
                version != 'HTTP/0.9'):
            self.send_error(wfile, 505, method, self.default_request_version,
                            "Invalid HTTP Version (%s)" % version)
            return ()

        logger.debug('parsing headers')
        headers = HeaderCollection.from_stream(rfile)
        for k, v in headers.iteritems():
            logger.debug('  {0}: "{1}"'.format(k, v))

        persistent_connection = False
        if (version == 'HTTP/1.1' and
                'Connection' in headers and
                headers['Connection'] != 'close'):
            persistent_connection = True

        logger.debug('reading body')
        body = read_body_from_stream(rfile, headers)

        logger.debug('returning')
        return (Request(method, path, headers, body), persistent_connection)

    def send_error(self, wfile, code, method, request_version, message=None):
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching the
        response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            short, long = messages_by_response_code[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        error_message_format = ("Error code %(code)d.\nMessage: %(message)s.\n"
                                "Error code explanation: %(code)s = "
                                "%(explain)s.")
        content = (error_message_format %
                   {'code': code, 'message': message,
                    'explain': explain})

        headers = {
            'Content-Type': "text/html",
            'Connection': 'close',
        }

        if method == 'HEAD' or code < 200 or code in (204, 304):
            content = ''

        response = Response(request_version, code, message, headers, content)

        self.send_response(response)

    def send_response(self, wfile, response):
        """
        Send the given Response over the socket. Add Server and Date headers
        if not already present.
        """

        message = response.message
        if message is None:
            if response.code in messages_by_response_code:
                message = messages_by_response_code[response.code][0]
            else:
                message = ''
        wfile.write("HTTP/1.1 %s %s\r\n" %
                    (response.code, message))

        for name, value in response.headers.iteritems():
            wfile.write("%s: %s\r\n" % (name, value))
        wfile.write("\r\n")

        if response.body is not None and len(response.body) > 0:
            logger.debug('Send the response body, len: %s',
                         len(response.body))
            wfile.write(response.body)

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)

        weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        monthname = [None,
                     'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (weekdayname[wd], day,
                                                     monthname[month], year,
                                                     hh, mm, ss)
        return s


# Table mapping response codes to messages; entries have the
# form {code: (shortmessage, longmessage)}.
# See RFC 2616.
messages_by_response_code = {
    100: ('Continue', 'Request received, please continue'),
    101: ('Switching Protocols',
          'Switching to new protocol; obey Upgrade header'),

    200: ('OK', 'Request fulfilled, document follows'),
    201: ('Created', 'Document created, URL follows'),
    202: ('Accepted',
          'Request accepted, processing continues off-line'),
    203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
    204: ('No Content', 'Request fulfilled, nothing follows'),
    205: ('Reset Content', 'Clear input form for further input.'),
    206: ('Partial Content', 'Partial content follows.'),

    300: ('Multiple Choices',
          'Object has several resources -- see URI list'),
    301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
    302: ('Found', 'Object moved temporarily -- see URI list'),
    303: ('See Other', 'Object moved -- see Method and URL list'),
    304: ('Not Modified',
          'Document has not changed since given time'),
    305: ('Use Proxy',
          'You must use proxy specified in Location to access this '
          'resource.'),
    307: ('Temporary Redirect',
          'Object moved temporarily -- see URI list'),

    400: ('Bad Request',
          'Bad request syntax or unsupported method'),
    401: ('Unauthorized',
          'No permission -- see authorization schemes'),
    402: ('Payment Required',
          'No payment -- see charging schemes'),
    403: ('Forbidden',
          'Request forbidden -- authorization will not help'),
    404: ('Not Found', 'Nothing matches the given URI'),
    405: ('Method Not Allowed',
          'Specified method is invalid for this resource.'),
    406: ('Not Acceptable', 'URI not available in preferred format.'),
    407: ('Proxy Authentication Required', 'You must authenticate with '
          'this proxy before proceeding.'),
    408: ('Request Timeout', 'Request timed out; try again later.'),
    409: ('Conflict', 'Request conflict.'),
    410: ('Gone',
          'URI no longer exists and has been permanently removed.'),
    411: ('Length Required', 'Client must specify Content-Length.'),
    412: ('Precondition Failed', 'Precondition in headers is false.'),
    413: ('Request Entity Too Large', 'Entity is too large.'),
    414: ('Request-URI Too Long', 'URI is too long.'),
    415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
    416: ('Requested Range Not Satisfiable',
          'Cannot satisfy request range.'),
    417: ('Expectation Failed',
          'Expect condition could not be satisfied.'),

    500: ('Internal Server Error', 'Server got itself in trouble'),
    501: ('Not Implemented',
          'Server does not support this operation'),
    502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
    503: ('Service Unavailable',
          'The server cannot process the request due to a high load'),
    504: ('Gateway Timeout',
          'The gateway server did not receive a timely response'),
    505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
}
