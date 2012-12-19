#!/usr/bin/env python

import requests
import threading
import socket
import time
import collections
import uuid
import select
import sys
import mimetools

Request = collections.namedtuple('Request', ['method', 'path', 'headers',
                                             'body'])
Response = collections.namedtuple('Response', ['code', 'message', 'headers',
                                               'body'])
Handling = collections.namedtuple('Handling', ['endpoint', 'request',
                                               'response'])


def default_handler(request):
    # returns a Response, comprised of status_code, status_message,
    # headers (list of key/value pairs), response_body (text or stream)
    return Response(200, 'OK', {}, '')


def echo_handler(request):
    return Response(200, 'OK', request.headers, request.body)


def delay_and_then(seconds, handler_function):
    def delay(request):
        time.sleep(seconds)
        return handler_function(request)
    return delay

request_id_header_name = 'Request-ID'


class MessageChain:
    def __init__(self, handler_function):
        self.handler_function = handler_function
        self.handlings = []
        self.lock = threading.Lock()

    def add_handling(self, handling):
        with self.lock:
            self.handlings.append(handling)


class Deproxy:
    def __init__(self, server_address=None):
        self.message_chains_lock = threading.Lock()
        self._message_chains = dict()
        self.endpoint_lock = threading.Lock()
        self._endpoints = []
        if server_address:
            self.add_endpoint(server_address)

    def make_request(self, url, method='GET', headers={}, request_body='',
                     handler_function=default_handler):

        request_id = str(uuid.uuid4())
        headers[request_id_header_name] = request_id

        message_chain = MessageChain(handler_function)
        self.add_message_chain(request_id, message_chain)

        req = requests.request(method, url, return_response=False,
                               headers=headers, data=request_body)
        req.send()
        resp = req.response

        self.del_message_chain(request_id)

        message_chain.sent_request = Request(req.method, req.path_url,
                                             req.headers, req.data)
        message_chain.received_response = Response(resp.status_code,
                                                   resp.raw.reason,
                                                   resp.headers,
                                                   resp.text)

        return message_chain

    def add_endpoint(self, server_address, name=None):
        endpoint = None
        with self.endpoint_lock:
            if name is None:
                name = 'Endpoint-%i' % len(self._endpoints)
            endpoint = DeproxyEndpoint(self, server_address, name)
            self._endpoints.append(endpoint)
            return endpoint

    def add_message_chain(self, request_id, message_chain):
        with self.message_chains_lock:
            self._message_chains[request_id] = message_chain

    def del_message_chain(self, request_id):
        with self.message_chains_lock:
            del self._message_chains[request_id]

    def get_message_chain(self, request_id):
        with self.message_chains_lock:
            if request_id in self._message_chains:
                return self._message_chains[request_id]
            else:
                return None


class DeproxyEndpoint:
    def __init__(self, deproxy, server_address, name):

        # BaseServer init
        self.server_address = server_address
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False

        # TCPServer init
        self.socket = socket.socket(self.address_family,
                                    self.socket_type)

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

        host, port = self.socket.getsockname()[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port

        self.socket.listen(self.request_queue_size)

        # DeproxyEndpoint init
        self.deproxy = deproxy
        self.name = name
        self.address = server_address

        server_thread = threading.Thread(target=self.serve_forever)
        server_thread.daemon = True
        server_thread.start()

    ### ThreadingMixIn
    daemon_threads = False

    def process_request_thread(self, request, client_address):
        """Same as in BaseServer but as a thread.

        In addition, exception handling is done here.

        """
        try:
            DeproxyRequestHandler(request, client_address, self)
        except:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    ### TCPServer

    address_family = socket.AF_INET

    socket_type = socket.SOCK_STREAM

    request_queue_size = 5

    def shutdown_request(self, request):
        """Called to shutdown and close an individual request."""
        try:
            #explicitly shutdown.  socket.close() merely releases
            #the socket and waits for GC to perform the actual close.
            request.shutdown(socket.SHUT_WR)
        except socket.error:
            pass  # some platforms may raise ENOTCONN here
        request.close()

    ### BaseServer

    def serve_forever(self, poll_interval=0.5):
        """Handle one request at a time until shutdown.

        Polls for shutdown every poll_interval seconds. Ignores
        self.timeout. If you need to do periodic tasks, do them in
        another thread.
        """
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
                        t = threading.Thread(
                            target=self.process_request_thread,
                            args=(request, client_address))
                        if self.daemon_threads:
                            t.setDaemon(1)
                        t.start()

                    except:
                        self.handle_error(request, client_address)
                        self.shutdown_request(request)

        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def shutdown(self):
        """Stops the serve_forever loop.

        Blocks until the loop has finished. This must be called while
        serve_forever() is running in another thread, or it will
        deadlock.
        """
        self.__shutdown_request = True
        self.__is_shut_down.wait()

    def handle_error(self, request, client_address):
        """Handle an error gracefully.  May be overridden.

        The default is to print a traceback and continue.

        """
        print '-' * 40
        print 'Exception happened during processing of request from',
        print client_address
        import traceback
        traceback.print_exc()  # XXX But this goes to stderr!
        print '-' * 40


class DeproxyRequestHandler:

    def __init__(self, connection, client_address, server):
        if self.disable_nagle_algorithm:
            connection.setsockopt(socket.IPPROTO_TCP,
                                       socket.TCP_NODELAY, True)
        rfile = connection.makefile('rb', -1)
        wfile = connection.makefile('wb', 0)

        try:
            self.close_connection = 1
            self.handle_one_request(rfile, wfile, server)
            while not self.close_connection:
                self.handle_one_request(rfile, wfile, server)
        finally:
            if not wfile.closed:
                wfile.flush()
            wfile.close()
            rfile.close()

    def handle_one_request(self, rfile, wfile, server):
        try:
            incoming_request = self.parse_request(rfile, wfile)
            if not incoming_request:
                # An error code has been sent, just exit
                return

            handler_function = default_handler
            message_chain = None
            if request_id_header_name in incoming_request.headers:
                request_id = incoming_request.headers[request_id_header_name]
                message_chain = server.deproxy.get_message_chain(
                    request_id)
                if message_chain:
                    handler_function = message_chain.handler_function

            resp = handler_function(incoming_request)

            if request_id_header_name in incoming_request.headers:
                resp.headers[request_id_header_name] = request_id

            outgoing_response = resp

            if message_chain is not None:
                message_chain.add_handling(Handling(server,
                                                    incoming_request,
                                                    outgoing_response))

            self.send_response(wfile, resp)

            wfile.flush()

        except socket.timeout, e:
            #a read or a write timed out.    Discard this connection
            self.close_connection = 1
            return

    def parse_request(self, rfile, wfile):
        requestline = rfile.readline(65537)
        if len(requestline) > 65536:
            self.request_version = ''
            self.send_error(wfile, 414, None)
            return ()
        if not requestline:
            self.close_connection = 1
            return ()
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        if requestline[-2:] == '\r\n':
            requestline = requestline[:-2]
        elif requestline[-1:] == '\n':
            requestline = requestline[:-1]
        words = requestline.split()
        if len(words) == 3:
            [method, path, version] = words
            if version[:5] != 'HTTP/':
                self.send_error(wfile, 400, method, "Bad request version (%r)" %
                                version)
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
                self.send_error(wfile, 400, method, "Bad request version (%r)" %
                                version)
                return ()
            if (version_number >= (1, 1) and
                    self.protocol_version >= "HTTP/1.1"):
                self.close_connection = 0
            if version_number >= (2, 0):
                self.send_error(wfile, 505, method,
                          "Invalid HTTP Version (%s)" % base_version_number)
                return ()
        elif len(words) == 2:
            [method, path] = words
            self.close_connection = 1
            if method != 'GET':
                self.send_error(wfile, 400, method,
                                "Bad HTTP/0.9 request type (%r)" % method)
                return ()
        elif not words:
            return ()
        else:
            self.send_error(wfile, 400, None, "Bad request syntax (%r)" %
                            requestline)
            return ()
        self.request_version = version

        # Examine the headers and look for a Connection directive
        headers = mimetools.Message(rfile, 0)

        conntype = headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0

        return Request(method, path, headers, rfile)

    def send_error(self, wfile, code, method, message=None):
        """Send and log an error reply.

        Arguments are the error code, and a detailed message.
        The detailed message defaults to the short entry matching the
        response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        # using _quote_html to prevent Cross Site Scripting attacks
        # (see bug #1100201)
        error_message_format = """Error code %(code)d.
Message: %(message)s.
Error code explanation: %(code)s = %(explain)s."""
        content = (error_message_format %
                   {'code': code, 'message': message,
                    'explain': explain})

        headers = {
            'Content-Type': "text/html",
            'Connection': 'close',
            }

        if method == 'HEAD' or code < 200 or code in (204, 304):
            content = ''

        response = Response(code, message, headers, content)

        self.send_response(response)

    def send_response(self, wfile, response):
        message = response.message
        if message is None:
            if response.code in self.responses:
                message = self.responses[response.code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, response.code, message))

        headers = dict(response.headers)
        lowers = {}

        for name, value in response.headers.items():
            name_lower = name.lower()
            lowers[name_lower] = value

        if 'server' not in lowers:
            headers['Server'] = self.version_string()
        if 'date' not in lowers:
            headers['Date'] = self.date_time_string()

        for name, value in headers.iteritems():
            if self.request_version != 'HTTP/0.9':
                wfile.write("%s: %s\r\n" % (name, value))
            if name.lower() == 'connection':
                if value.lower() == 'close':
                    self.close_connection = 1
                elif value.lower() == 'keep-alive':
                    self.close_connection = 0

        # Send the blank line ending the MIME headers.
        if self.request_version != 'HTTP/0.9':
            wfile.write("\r\n")

        # Send the response body
        wfile.write(response.body)

    def version_string(self):
        """Return the server software version string."""
        return self.server_version + ' ' + self.sys_version

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    # The Python system version, truncated to its first component.
    sys_version = "Python/" + sys.version.split()[0]

    # The server software version.  You may want to override this.
    # The format is multiple whitespace-separated strings,
    # where each string is of the form name[/version].
    server_version = "Deproxy/0.1"

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    # Most web servers default to HTTP 0.9, i.e. don't send a status line.
    default_request_version = "HTTP/0.9"

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    # Essentially static class variables

    # The version of the HTTP protocol we support.
    # Set this to HTTP/1.1 to enable automatic keepalive
    protocol_version = "HTTP/1.0"

    # Table mapping response codes to messages; entries have the
    # form {code: (shortmessage, longmessage)}.
    # See RFC 2616.
    responses = {
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

    # Default buffer sizes for rfile, wfile.
    # We default rfile to buffered because otherwise it could be
    # really slow for large data (a getc() call per byte); we make
    # wfile unbuffered because (a) often after a write() we want to
    # read and we need to flush the line; (b) big writes to unbuffered
    # files are typically optimized by stdio even when big reads
    # aren't.

    # Disable nagle algoritm for this socket, if True.
    # Use only when wbufsize != 0, to avoid small packets.
    disable_nagle_algorithm = False
