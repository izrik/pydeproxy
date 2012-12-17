#!/usr/bin/env python

import BaseHTTPServer
import SocketServer
import os
import requests
import threading
import socket
import inspect
import time
import collections
import uuid

Request = collections.namedtuple('Request', ['method', 'path', 'headers', 'body'])
Response = collections.namedtuple('Response', ['code', 'message', 'headers', 'body'])

def log(s):
    f = inspect.getouterframes(inspect.currentframe(),1)[1]
    t = threading.current_thread()
    print '[%s : %s(%i) : %s : %s (%i)] %s' % (time.ctime(), f[1], f[2], f[3], t.name, t.ident, s)

def handler2(request):
    log('in handler2')
    return Response(601, 'Something', {'X-Header': 'Value'}, 'this is the body')

def default_handler(request):
    log('in default_handler')
    # returns a Response, comprised of status_code, status_message, headers (list of key/value pairs), response_body (text or stream)
    return Response(200, 'OK', {}, '')

request_id_header_name = 'Request-ID'

class MessageChain:
    def __init__(self, handler_function):
        self.handler_function = handler_function
        self.handlings = []
        self.lock = threading.Lock()
        
    def add_handling(self, handling):
        self.lock.acquire()
        try:
            self.handlings.append(handling)
        finally:
            self.lock.release()

class Deproxy:
    def __init__(self, server_address):
        self.message_chains = dict()
        self.endpoint = DeproxyHTTPServer(server_address, self.message_chains)

    def make_request(self, url, method='GET', headers={}, request_body='', handler_function=default_handler):
        log('in make_request(%s, %s, %s, %s)' % (url, method, headers, request_body))

        request_id = str(uuid.uuid4())
        headers[request_id_header_name] = request_id

        self.message_chains[request_id] = MessageChain(handler_function)

        req = requests.request(method, url, return_response=False, headers=headers, data=request_body)
        req.send()
        resp = req.response

        del self.message_chains[request_id]

        sent_request = Request(req.method, req.path_url, req.headers, req.data)
        received_response = Response(resp.status_code, resp.raw.reason, resp.headers, resp.text)

        return sent_request, received_response


class DeproxyHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, message_chains):
        log('in DeproxyHTTPServer.__init__')
        BaseHTTPServer.HTTPServer.__init__(self, server_address, self.instantiate)

        self.message_chains = message_chains

        log('Creating server thread')
        server_thread = threading.Thread(target=self.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        log('Thread started')

    def instantiate(self, request, client_address, server):
        log('in instantiate')
        return DeproxyRequestHandler(request, client_address, server)

    def process_request_thread(self, request, client_address):
        log('override process_request_thread')
        SocketServer.ThreadingMixIn.process_request_thread(self, request, client_address)

    def process_request(self, request, client_address):
        log('override process_request')
        SocketServer.ThreadingMixIn.process_request(self, request, client_address)

class DeproxyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        log('in DeproxyRequestHandler.__init__')
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

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

            self.incoming_request = Request(self.command, self.path, self.headers, self.rfile)

            handler_function = default_handler
            if request_id_header_name in self.headers:
                request_id = self.headers[request_id_header_name]
                if request_id in self.server.message_chains:
                    handler_function = self.server.message_chains[request_id].handler_function

            resp = handler_function(self.incoming_request)

            if request_id_header_name in self.headers:
                resp.headers[request_id_header_name] = request_id

            self.outgoing_response = resp

            response_code = resp[0]
            response_message = resp[1]
            response_headers = resp[2]
            response_body = resp[3]

            self.send_response(response_code, response_message)
            for name, value in response_headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response_body)

            self.wfile.flush() #actually send the response if not already done.

        except socket.timeout, e:
            #a read or a write timed out.    Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

def print_request(request, heading=None):
    if heading:
        print heading
    print '    method: %s' % request.method
    print '    path: %s' % request.path
    print '    headers:'
    for name, value in request.headers.items():
        print '        %s: %s' % (name, value)
    print '    body: %s' % request.body
    print ''

def print_response(response, heading=None):
    if heading:
        print heading
    print '    status code: %s' % response.code
    print '    message: %s' % response.message
    print '    Headers: '
    for name, value in response.headers.items():
        print '        %s: %s' % (name, value)
    print '    Body:'
    print response.body

def run():
    server = 'localhost'
    port = 8081
    server_address = (server, port)

    log('Creating receiver')
    deproxy = Deproxy(server_address)

    target = server

    url = 'http://%s:%i/abc/123' % (target, port);

    print
    log('making request')
    sent_request, received_response = deproxy.make_request(url, 'GET')
    print
    print_request(sent_request, 'Sent Request')
    print_response(received_response, 'Received Response')

    print
    log('making request')
    sent_request, received_response = deproxy.make_request(url, 'GET', handler_function=handler2)
    print
    print_request(sent_request, 'Sent Request')
    print_response(received_response, 'Received Response')

if __name__ == '__main__':
    run()
