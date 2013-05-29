
import logging
import time

from .response import Response
from .request import Request

logger = logging.getLogger(__name__)


def default_handler(request):
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


def delay(timeout, handler_function):
    """
    Factory function.
    Returns a handler that delays the request for the specified number of
    seconds, forwards it to the next handler function, and returns that
    handler function's Response.
    """
    def delayer(request):
        logger.debug('delaying for %i seconds' % timeout)
        time.sleep(timeout)
        return handler_function(request)

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
        logger.debug('request = %s,%s,%s' % (request.method, request.path,
                                             request.protocol))
        logger.debug('scheme, host = %s, %s' % (scheme, host))
        request2 = Request(request.method, request.path, 'HTTP/1.0',
                           request.headers, request.body)
        if 'Host' in request2.headers:
            request2.headers.delete_all('Host')
        logger.debug('sending request')
        response = deproxy.send_request(scheme, host, request2)
        logger.debug('received response')
        return response, False

    route_to_host.__doc__ = "Route responses to %s using %s" % (host, scheme)

    return route_to_host
