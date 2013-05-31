==========
 Handlers
==========

Handlers are the things that turn requests into responses. A given call to
make_request can take a ``handler`` argument that will be called for each
request that reaches an endpoint. Deproxy includes a number of built-in
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
            default_handler=deproxy.echo_handler).received_response.headers
    [('Deproxy-Request-ID', 'ce999e6a-2111-4bc1-ab4e-22965fb790a9'),
     ('Host', 'localhost:9999'),
     ('Accept', '*/*'),
     ('Accept-Encoding', 'identity, deflate, compress, gzip'),
     ('User-Agent', 'Deproxy/0.6 Python/2.7.3'),
     ('Server', 'Deproxy/0.6 Python/2.7.3'),
     ('Date', 'Fri, 31 May 2013 13:41:43 GMT')]

Specifying Handlers
===================

Handlers can be specified in multiple ways, depending on your needs.

- Passing a handler as the ``default_handler`` parameter when creating a
  ``Deproxy`` object will set the handler to be used for every request serviced
  by any endpoint on that object. This covers every request coming in, whether
  it is originally initiated by some call ``make_request`` (simply called a
  'handling') or by some other client (called an 'orphaned handling' because it
  isn't tied to any single message chain).

    >>> slow_server = deproxy.Deproxy(default_handler=deproxy.delay(10))

- Passing a handler as the ``default_handler`` parameter to ``add_endpoint``
  will set the handler to be used for every request that the created endpoint
  receives, whether normal or orhpaned.

    >>> d = deproxy.Deproxy()
    >>> d.add_endpoint(port=9999, name='somewhere-else',
                       default_handler=deproxy.route('http', 'www.example.com', d))
    <deproxy.DeproxyEndpoint instance at 0x...>

- Passing a handler as the ``default_handler`` parameter to ``make_request``
  will set the handler used for every request associated with the message
  chain, no matter which endpoint receives it. This does not affect orphaned
  requests from non-deproxy clients, or requests that lose their
  ``Deproxy-Request-ID`` header for some reason.

    >>> mc = d.make_request(url='http://localhost:9999/',
                            default_handler=deproxy.echo_handler)

- Passing a ``dict`` or other mapping object as the ``handlers`` parameter to
  ``make_request`` will specify specific handlers to be used for specific
  endpoints for all requests received associated with the message chain. This
  does not affect orphaned requests. The mapping object must have endpoint
  objects (or their names) as keys, and the handlers as values.

    >>> d = deproxy.Deproxy()
    >>> endpoint1 = d.add_endpoint(port=9999, name='endpoint-1')
    >>> endpoint2 = d.add_endpoint(port=9998, name='endpoint-2')
    >>> endpoint3 = d.add_endpoint(port=9997, name='endpoint-3')
    >>> mc = d.make_request(url='http://localhost:9999/',
                            handlers={
                                endpoint1: custom_handler1,
                                endpoint2: custom_handler2,
                                'endpoint-3': custom_handler3
                            })

Handler Resolution Procedure
----------------------------

Given the various ways to specify handlers, and the different needs for each,
there must be one way to unambiguously determine which handler to use for any
given request. When an endpoint receives and services a request, the process by
which a handler is chosen for it is defined so:

    1. If the incoming request is tied to a particular message chain by the
       presence of a ``Deproxy-Request-ID`` header, and the call to
       ``make_request`` includes a ``handlers`` parameters,

        a. if that ``handlers`` mapping object has the current servicing
           endpoint as a key, use the associated value as the handler.
        b. if the mapping object doesn't have the current servicing endpoint as
           a key, but does have the endpoint's *name* as a key, then use the
           associated value of the name as the handler.
        c. otherwise, continue below
    2. If the call to ``make_request`` didn't have a ``handlers`` argument or
       if the servicing endpoint was not found therein, but the call to
       ``make_request`` *did* include a ``default_handler`` argument, use that
       as the handler.
    3. If the incoming request cannot be tied to a particular message chain,
       but the servicing endpoint's ``default_handler`` attribute is not
       `None`, then use the value of that attribute as the handler.
    4. If the servicing endpoint's ``default_handler`` is None, but the parent
       ``Deproxy`` object's ``default_handler`` attribute is not `None`, then
       use that as the handler.
    5. Otherwise, use ``deproxy.simple_handler`` as a last resort.

Built-in Handlers
=================

The following handlers are a part of the deproxy module. They can be used to
address a small number of potential use cases. They also demonstrate effective
ways to define additional handlers.

- simple_handler
    The last-resort handler used if none is specified. It returns a response
    with a 200 status code, an empty response body, and only the basic Date,
    Server, and request id headers.

- echo_handler
    Returns a response with a 200 status code, and copies the request body and
    request headers.

- delay(timeout, next_handler)
    This is actually a factory function that returns a handler. Give it a
    time-out in seconds and a second handler function, and it will return a
    handler that will wait the desired amount of time before calling the second
    handler.

- route(scheme, host, deproxy)
    This is actually a factory function that returns a handler. The handler
    forwards all requests to the specified host via HTTP or HTTPS, as indicated
    by the scheme parameter. The deproxy parameter is a deproxy.Deproxy object,
    which is used only as an HTTP/S client. The response returned from the
    handler is the response returned from the specified host.

Custom Handlers
===============

You can define your own handlers and pass them as the ``handler`` parameter to
make_request. Any callable that accepts a single ``request`` parameter and
returns a ``Response`` object will do.
::

    >>> def custom_handler(request):
            return deproxy.Response(code=606, message='Spoiler', headers={},
                                    body='Snape Kills Dumbledore')
    >>> d.make_request('http://localhost:9999/',
                       default_handler=custom_handler).received_response
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
useful for testing how a proxy responds to a misbehaving origin server.
::

    >>> def custom_handler2(request):
            return (deproxy.Response(code=503, message='Something went wrong.',
                                     headers={},
                                     body='Something went wrong in the server '
                                     'and it didn\'t return correct headers!'),
                    False)
    >>> d.make_request('http://localhost:9999/',
                       default_handler=custom_handler2).received_response
    Response(code='503', message='Something went wrong.', headers=[
        ('Content-Length', '72'),
        ('Deproxy-Request-ID', 'dbc2acc9-d5bd-4e68-bd31-41371704dfb6')],
        body="Something went wrong in the server and it didn't return correct headers!")

Additionally, any response from a handler that has a response body will have an
additional ``Content-Length`` header added to it, giving the length of the
response body. This *cannot* be turned off.