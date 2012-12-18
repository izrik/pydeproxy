#!/usr/bin/env python

import deproxy

def handler2(request):
    deproxy.log('in handler2')
    return deproxy.Response(601, 'Something', {'X-Header': 'Value'}, 'this is the body')

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

def print_message_chain(mc, heading=None):
    if heading:
        print heading
    print_request(mc.sent_request, 'Sent Request')
    for h in mc.handlings:
        print 'Endpoint: "%s (%s:%i)' % (h.endpoint.name, h.endpoint.address[0], h.endpoint.address[1])
        print_request(h.request, '  Received Request')
        print_response(h.response, '  Sent Response')
    print_response(mc.received_response, 'Received Response')

def run():
    server = 'localhost'
    port = 8081
    server_address = (server, port)

    deproxy.log('Creating receiver')
    d = deproxy.Deproxy(server_address)
    d.add_endpoint((server, port+1))

    target = server

    url = 'http://%s:%i/abc/123' % (target, port);
    url2 = 'http://%s:%i/abc/123' % (target, port+1);

    print
    deproxy.log('making request')
    mc = d.make_request(url, 'GET')
    print
    print_message_chain(mc)

    print
    deproxy.log('making request')
    mc = d.make_request(url2, 'GET', handler_function=handler2)
    print
    print_message_chain(mc)

    print
    deproxy.log('making request')
    mc = d.make_request(url2, 'GET', handler_function=deproxy.echo_handler)
    print
    print_message_chain(mc)

if __name__ == '__main__':
    run()
