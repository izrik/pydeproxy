#!/usr/bin/env python

import BaseHTTPServer
import SocketServer
import requests
import threading
import socket
import inspect
import time
import collections
import uuid
import select

Request = collections.namedtuple('Request', ['method', 'path', 'headers',
                                             'body'])
Response = collections.namedtuple('Response', ['code', 'message', 'headers',
                                               'body'])
Handling = collections.namedtuple('Handling', ['endpoint', 'request',
                                               'response'])


def log(s):
    f = inspect.getouterframes(inspect.currentframe(), 1)[1]
    t = threading.current_thread()
    print '[%s : %s(%i) : %s : %s (%i)] %s' % (time.ctime(), f[1], f[2], f[3],
                                               t.name, t.ident, s)


def default_handler(request):
    log('in default_handler')
    # returns a Response, comprised of status_code, status_message,
    # headers (list of key/value pairs), response_body (text or stream)
    return Response(200, 'OK', {}, '')


def echo_handler(request):
    log('in echo_handler')
    return Response(200, 'OK', request.headers, request.body)

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
        log('in make_request(%s, %s, %s, %s)' % (url, method, headers,
                                                 request_body))

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
        log('in DeproxyHTTPServer.__init__')

        # BaseServer init
        self.server_address = server_address
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False

        # TCPServer init
        self.socket = socket.socket(self.address_family,
                                    self.socket_type)

        if self.allow_reuse_address:
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

        log('Creating server thread')
        server_thread = threading.Thread(target=self.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        log('Thread started')

    def instantiate(self, request, client_address, server):
        log('in instantiate')
        return DeproxyRequestHandler(request, client_address, server)

    ### ThreadingMixIn
    daemon_threads = False

    def process_request_thread(self, request, client_address):
        """Same as in BaseServer but as a thread.

        In addition, exception handling is done here.

        """
        try:
            self.instantiate(request, client_address, self)
            self.shutdown_request(request)
        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

    ### HTTPServer

    allow_reuse_address = 1    # Seems to make sense in testing environment

    ### TCPServer

    address_family = socket.AF_INET

    socket_type = socket.SOCK_STREAM

    request_queue_size = 5

    TCPServer_allow_reuse_address = False

    def fileno(self):
        """Return socket file number.

        Interface required by select().

        """
        return self.socket.fileno()

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

    timeout = None

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
                r, w, e = select.select([self], [], [], poll_interval)
                if self in r:
                    self._handle_request_noblock()
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

    # The distinction between handling, getting, processing and
    # finishing a request is fairly arbitrary.  Remember:
    #
    # - handle_request() is the top-level call.  It calls
    #   select, get_request(), verify_request() and process_request()
    # - get_request() is different for stream or datagram sockets
    # - process_request() is the place that may fork a new process
    #   or create a new thread to finish the request
    # - finish_request() instantiates the request handler class;
    #   this constructor will handle the request all by itself

    def _handle_request_noblock(self):
        """Handle one request, without blocking.

        I assume that select.select has returned that the socket is
        readable before this function was called, so there should be
        no risk of blocking in get_request().
        """
        try:
            request, client_address = self.socket.accept()
        except socket.error:
            return

        try:
            t = threading.Thread(target=self.process_request_thread,
                                 args=(request, client_address))
            if self.daemon_threads:
                t.setDaemon(1)
            t.start()

        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

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


class DeproxyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        log('in DeproxyRequestHandler.__init__')
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request,
                                                       client_address, server)

    def handle(self):
        log('override handle')
        BaseHTTPServer.BaseHTTPRequestHandler.handle(self)

    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.

        """
        log('in handle_one_request()')
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return

            incoming_request = Request(self.command, self.path, self.headers,
                                       self.rfile)

            handler_function = default_handler
            message_chain = None
            if request_id_header_name in self.headers:
                request_id = self.headers[request_id_header_name]
                message_chain = self.server.deproxy.get_message_chain(
                    request_id)
                if message_chain:
                    handler_function = message_chain.handler_function

            resp = handler_function(incoming_request)

            if request_id_header_name in self.headers:
                resp.headers[request_id_header_name] = request_id

            outgoing_response = resp

            if message_chain is not None:
                message_chain.add_handling(Handling(self.server,
                                                    incoming_request,
                                                    outgoing_response))

            self.send_response(resp.code, resp.message)
            for name, value in resp.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(resp.body)

            self.wfile.flush()

        except socket.timeout, e:
            #a read or a write timed out.    Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return
