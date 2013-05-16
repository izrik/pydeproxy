==========
 Handlers
==========

Handlers are the things that turn requests into responses. A given call to
make_request can take a `handler_function` argument that will be called for
each request that reaches an endpoint. Deproxy includes a number of built-in
handlers for some of the most common use cases. Also, you can define your own
handlers.
::

    >>> d = deproxy.Deproxy()
    >>> e = d.add_endpoint(('localhost', 9999))
    >>> d.make_request('http://localhost:9999/').received_response.headers
    {'date': 'Fri, 05 Apr 2013 21:56:22 GMT',
     'deproxy-request-id': 'f9eb8462-c7b8-4a23-aeca-78ea5244755e',
     'server': 'Deproxy/0.1.5 Python/2.7.3'}

    >>> d.make_request('http://localhost:9999/',
            handler_function=deproxy.echo_handler).received_response.headers
    {'host': 'localhost:9999',
     'accept-encoding': 'identity, deflate, compress, gzip',
     'date': 'Fri, 05 Apr 2013 21:56:29 GMT',
     'deproxy-request-id': 'f9be28a9-4e58-404b-9333-300752ecc235',
     'user-agent': 'Deproxy/0.1.5 Python/2.7.3',
     'accept': '*/*',
     'server': 'Deproxy/0.1.5 Python/2.7.3'}

Built-in Handlers
=================

- default_handler
The default handler used if none is specified. It returns a response with a 200
status code, an empty response body, and only the basic Date, Server, and
request id headers.

- echo_handler
Returns a response with a 200 status code, and copies the request body and
request headers.

- delay(timeout, handler_function)
This is actually a factory function that returns a handler. Give it a time-out
in seconds and a second handler function, and it will return a handler that
will wait the desired amount of time before calling the second handler.

- route(scheme, host, deproxy)
This is actually a factory function that returns a handler. The handler
forwards all requests to the specified host via HTTP or HTTPS, as indicated by
the scheme parameter. The deproxy parameter is a deproxy.Deproxy object, which
is used only as an HTTP/S client. The response returned from the handler is the
response returned from the specified host.

Custom Handlers
===============

You can define your own handlers and pass them as the handler_function
parameter to make_request. Any callable that accepts a single Request parameter
and returns a Response object will do.::
    >>> def custom_handler(request):
            return deproxy.Response(code=606, message='Spoiler', headers={},
                                    body='Snape Kills Dumbledore')
    >>> d.make_request('http://localhost:9999/',
                    handler_function=custom_handler).received_response
    Response(code='606', message='Spoiler', headers={
        'date': 'Fri, 05 Apr 2013 22:04:48 GMT',
        'deproxy-request-id': '324b75f5-887e-4200-a476-775cffad321d',
        'server': 'Deproxy/0.1.5 Python/2.7.3'},
        body=<socket._fileobject object at 0x100468dd0>)

* The response body is not correctly converted into a string. This is a known
defect.

Default Response Headers
========================

By default, an endpoint will add the 'Server' and 'Date' headers on all
out-bound responses. This can be turned off in custom handlers by returning a
2-value tuple, with the first value being the `Response` object (as usual) and
the second value being `True` or `False` to indicate whether the default
response headers should or should not be added, respectively. This can be
useful for testing how a proxy responds to a misbehaving origin server.::

    >>> def custom_handler2(request):
        return (deproxy.Response(code=503, message='Something went wrong.',
                                 headers={},
                                 body='Something went wrong in the server and '
                                 'it didn\'t return correct headers!'),
                False)
    >>> d.make_request('http://localhost:9999/',
                       handler_function=custom_handler2).received_response
    Response(code='503', message='Something went wrong.', headers={
    'deproxy-request-id': '6f714468-dcd5-4d97-bff2-1b4ba6a8877b'},
    body=<socket._fileobject object at 0x1004a46d0>)
