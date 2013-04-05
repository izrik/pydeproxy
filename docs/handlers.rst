==========
 Handlers
==========

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

default_handler
echo_handler
delay_and_then(seconds, handler_function)
route(scheme, host, deproxy)

Custom Handlers
===============

::
    >>> def custom_handler(request):
            return deproxy.Response(code=606, message='Spoiler', headers={},
                                    body='Snape Kills Dumbledore')
    >>> d.make_request('http://localhost:9999/',
                    handler_function=deproxy.echo_handler).received_response
    Response(code='606', message='Spoiler', headers={
        'date': 'Fri, 05 Apr 2013 22:04:48 GMT',
        'deproxy-request-id': '324b75f5-887e-4200-a476-775cffad321d',
        'server': 'Deproxy/0.1.5 Python/2.7.3'},
        body=<socket._fileobject object at 0x100468dd0>)

* The response body is not correctly converted into a string. This is a known defect.
