#!/usr/bin/env python

import deproxy
import threading


def handler2(request):
    return deproxy.Response('HTTP/1.0', 601, 'Something', {'X-Header': 'Value'},
                            'this is the body')


def print_request(request, heading=None, indent=''):
    if heading:
        print '%s%s' % (indent, heading)
    print '%s  method: %s' % (indent, request.method)
    print '%s  path: %s' % (indent, request.path)
    print '%s  headers:' % indent
    for name, value in request.headers.items():
        print '%s    %s: %s' % (indent, name, value)
    print '%s  body: %s' % (indent, request.body)

def print_response(response, heading=None, indent=''):
    if heading:
        print '%s%s' % (indent, heading)
    print '%s  status code: %s' % (indent, response.code)
    print '%s  message: %s' % (indent, response.message)
    print '%s  Headers: ' % indent
    for name, value in response.headers.items():
        print '%s    %s: %s' % (indent, name, value)
    print '%s  Body: %s' % (indent, response.body)

_print_lock = threading.Lock()
def print_message_chain(mc, heading=None):
    with _print_lock:
        if heading:
            print heading
        print_request(mc.sent_request, 'Sent Request', '    ')
        i = 0
        for h in mc.handlings:
            print '    Handling %i: "%s (%s:%i)' % (i, h.endpoint.name,
                                                       h.endpoint.address[0],
                                                       h.endpoint.address[1])
            print_request(h.request, 'Received Request', '        ')
            print_response(h.response, 'Sent Response', '        ')
            i += 1
        print_response(mc.received_response, 'Received Response', '    ')
        print
        print

def do_request_async(d, url, method, handler_function, name):
    t = threading.Thread(target=do_request_async_target,
                         name=('Client %s' % name),
                         args=(d, url, method, handler_function))
    t.start()


def do_request_async_target(d, url, method, handler_function):
    mc = d.make_request(url, method, handler_function=handler_function)
    print_message_chain(mc)


def run():
    server = 'localhost'
    port = 8081
    server_address = (server, port)

    d = deproxy.Deproxy()
    d.add_endpoint((server, port))
    d.add_endpoint((server, port + 1))

    target = server

    url = 'http://%s:%i/abc/123' % (target, port)
    url2 = 'http://%s:%i/abc/123' % (target, port + 1)

    print "======== Normal Functionality ========"

    mc = d.make_request(url, 'GET')
    print_message_chain(mc)

    mc = d.make_request(url2, 'GET', handler_function=handler2)
    print_message_chain(mc)

    mc = d.make_request(url2, 'GET', handler_function=deproxy.echo_handler)
    print_message_chain(mc)

    print "======== Multi-threaded Functionality ========"

    do_request_async(d, url, 'GET',
                     deproxy.delay_and_then(2, deproxy.echo_handler),
                     'mt-1')

    do_request_async(d, url2, 'GET', deproxy.default_handler, 'mt-2')
    do_request_async(d, url, 'GET', handler2, 'mt-3')

if __name__ == '__main__':
    run()
