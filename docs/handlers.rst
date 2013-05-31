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
    >>> e = d.add_endpoint(port=9999)
    >>> d.make_request('http://localhost:9999/').received_response.headers
    [('Server', 'Deproxy/0.6 Python/2.7.3'),
     ('Date', 'Fri, 31 May 2013 13:41:02 GMT'),
     ('Deproxy-Request-ID', 'e956085c-bd8f-40e8-ac3e-a13d11613f6c')]

    >>> d.make_request('http://localhost:9999/',
            handler_function=deproxy.echo_handler).received_response.headers
    [('Deproxy-Request-ID', 'ce999e6a-2111-4bc1-ab4e-22965fb790a9'),
     ('Host', 'localhost:9999'),
     ('Accept', '*/*'),
     ('Accept-Encoding', 'identity, deflate, compress, gzip'),
     ('User-Agent', 'Deproxy/0.6 Python/2.7.3'),
     ('Server', 'Deproxy/0.6 Python/2.7.3'),
     ('Date', 'Fri, 31 May 2013 13:41:43 GMT')]

Built-in Handlers
=================

- simple_handler
The last-resort handler used if none is specified. It returns a response with a
200 status code, an empty response body, and only the basic Date, Server, and
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
    Response(code='606', message='Spoiler', headers=[
        ('Content-Length', '22'),
        ('Server', 'Deproxy/0.6 Python/2.7.3'),
        ('Date', 'Fri, 31 May 2013 14:03:46 GMT'),
        ('Deproxy-Request-ID', 'c854be6f-d0ec-4232-88b4-d0389f309ffa')],
        body='Snape Kills Dumbledore')

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
                                     body='Something went wrong in the server '
                                     'and it didn\'t return correct headers!'),
                    False)
    >>> d.make_request('http://localhost:9999/',
                       handler_function=custom_handler2).received_response
    Response(code='503', message='Something went wrong.', headers=[
        ('Content-Length', '72'),
        ('Deproxy-Request-ID', 'dbc2acc9-d5bd-4e68-bd31-41371704dfb6')],
        body="Something went wrong in the server and it didn't return correct headers!")
