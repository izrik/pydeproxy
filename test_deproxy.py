#!/usr/bin/python

import sys

import deproxy
import unittest
import threading
import logging
import socket
import argparse
import time

deproxy_port_base = 9999
deproxy_port_iter = None


def get_next_deproxy_port():
    global deproxy_port_iter
    if deproxy_port_iter is None:
        def deproxy_port_iter_func():
            for i in xrange(deproxy_port_base):
                yield deproxy_port_base - i
        deproxy_port_iter = deproxy_port_iter_func().next
    return deproxy_port_iter()


class TestDefaultHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_default_handler(self):
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestEchoHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_echo_handler(self):
        headers = {'x-header': '12345'}
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port, headers=headers,
                                       request_body='this is the body',
                                       handler_function=deproxy.echo_handler)
        self.assertEquals(int(mc.received_response.code), 200)
        self.assertTrue('x-header' in mc.received_response.headers,
                        msg=('\'x-header\' not in %s' %
                             mc.received_response.headers))
        self.assertEquals(mc.received_response.headers['x-header'], '12345')
        self.assertEquals(mc.received_response.body, 'this is the body')


class TestDelayHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_delay_handler(self):
        handler = deproxy.delay(3, deproxy.default_handler)
        t1 = time.time()
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port,
                                       handler_function=handler)
        t2 = time.time()
        self.assertEquals(int(mc.received_response.code), 200)
        self.assertGreaterEqual(t2 - t1, 3)
        self.assertLessEqual(t2 - t1, 3.5)


class TestRoute(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))
        self.handler = deproxy.route('http', 'github.com', self.deproxy)

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_route(self):
        mc = self.deproxy.make_request('http://localhost:%i/izrik/deproxy' %
                                       self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestCustomHandlers(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_custom_handler_function(self):
        def custom_handler(request):
            return deproxy.Response(code=606, message="Spoiler",
                                    headers={"Header-Name": "Header-Value"},
                                    body='Snape Kills Dumbledore')
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port,
                                       handler_function=custom_handler)
        self.assertEquals(int(mc.received_response.code), 606)

    def handler_method(self, request):
        return deproxy.Response(code=606, message="Spoiler",
                                headers={"Header-Name": "Header-Value"},
                                body='Snape Kills Dumbledore')

    def test_custom_handler_method(self):
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port,
                                       handler_function=self.handler_method)
        self.assertEquals(int(mc.received_response.code), 606)


class TestOrphanedHandlings(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))
        self.other_client = deproxy.Deproxy()

    def tearDown(self):
        self.deproxy.shutdown_all_endpoints()

    def test_orphaned_handling(self):
        delayed_handler = deproxy.delay(2, deproxy.default_handler)
        self.long_running_mc = None

        class Helper:
            mc = None

        helper = Helper()

        def other_thread():
            mc = self.deproxy.make_request('http://localhost:%i/' %
                                           self.deproxy_port,
                                           handler_function=delayed_handler)
            helper.mc = mc

        t = threading.Thread(target=other_thread)
        t.daemon = True
        t.start()
        self.other_client.make_request('http://localhost:%i/' %
                                       self.deproxy_port)
        t.join()
        self.assertEqual(len(helper.mc.orphaned_handlings), 1)


class TestEndpointShutdown(unittest.TestCase):
    def setUp(self):
        self.deproxy_port1 = get_next_deproxy_port()
        self.deproxy_port2 = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()

    def test_shutdown(self):
        e1 = self.deproxy.add_endpoint(('localhost', self.deproxy_port1))
        e2 = self.deproxy.add_endpoint(('localhost', self.deproxy_port2))

        e1.shutdown()

        try:
            e3 = self.deproxy.add_endpoint(('localhost', self.deproxy_port1))
        except socket.error as e:
            self.fail('Address already in use: %s' % e)


class TestShutdownAllEndpoints(unittest.TestCase):
    def setUp(self):
        self.deproxy_port1 = get_next_deproxy_port()
        self.deproxy_port2 = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()

    def test_shutdown(self):
        e1 = self.deproxy.add_endpoint(('localhost', self.deproxy_port1))
        e2 = self.deproxy.add_endpoint(('localhost', self.deproxy_port2))

        self.deproxy.shutdown_all_endpoints()

        try:
            e3 = self.deproxy.add_endpoint(('localhost', self.deproxy_port1))
        except socket.error as e:
            self.fail('add_endpoint through an exception: %s' % e)

        try:
            e4 = self.deproxy.add_endpoint(('localhost', self.deproxy_port2))
        except socket.error as e:
            self.fail('add_endpoint through an exception: %s' % e)


class TestAutomaticRequestHeaders(unittest.TestCase):
    def setUp(self):
        self.port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.endpoint = self.deproxy.add_endpoint(('localhost', self.port))
        self.url = 'http://localhost:{}/'.format(self.port)

    def tearDown(self):
        if self.deproxy is not None:
            self.deproxy.shutdown_all_endpoints()

    def test_not_specified(self):
        mc = self.deproxy.make_request(url=self.url)
        self.assertIn('Host', mc.sent_request.headers)
        #self.assertIn('host', mc.sent_request.headers)
        self.assertIn('Accept', mc.sent_request.headers)
        self.assertIn('Accept-Encoding', mc.sent_request.headers)
        self.assertIn('User-Agent', mc.sent_request.headers)

    def test_explicit_on(self):
        mc = self.deproxy.make_request(url=self.url, add_default_headers=True)
        self.assertIn('Host', mc.sent_request.headers)
        #self.assertIn('host', mc.sent_request.headers)
        self.assertIn('Accept', mc.sent_request.headers)
        self.assertIn('Accept-Encoding', mc.sent_request.headers)
        self.assertIn('User-Agent', mc.sent_request.headers)

    def test_explicit_off(self):
        mc = self.deproxy.make_request(url=self.url, add_default_headers=False)
        self.assertNotIn('Host', mc.sent_request.headers)
        #self.assertNotIn('host', mc.sent_request.headers)
        self.assertNotIn('Accept', mc.sent_request.headers)
        self.assertNotIn('Accept-Encoding', mc.sent_request.headers)
        self.assertNotIn('User-Agent', mc.sent_request.headers)


class TestDefaultResponseHeaders(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.endpoint = self.deproxy.add_endpoint(('localhost', self.port))
        self.url = 'http://localhost:{}/'.format(self.port)

    @classmethod
    def tearDownClass(self):
        if self.deproxy is not None:
            self.deproxy.shutdown_all_endpoints()

    def handler1(self, request):
        return deproxy.Response(code=606, message="Spoiler",
                                headers={"Header-Name": "Header-Value"},
                                body='Snape Kills Dumbledore')

    def handler2(self, request):
        return (deproxy.Response(code=606, message="Spoiler",
                                 headers={"Header-Name": "Header-Value"},
                                 body='Snape Kills Dumbledore'), True)

    def handler3(self, request):
        return (deproxy.Response(code=606, message="Spoiler",
                                 headers={"Header-Name": "Header-Value"},
                                 body='Snape Kills Dumbledore'), False)

    def test_not_specified(self):
        mc = self.deproxy.make_request(url=self.url,
                                       handler_function=self.handler1)
        self.assertIn('server', mc.received_response.headers)
        self.assertIn('date', mc.received_response.headers)
        self.assertIn('Server', mc.handlings[0].response.headers)
        self.assertIn('Date', mc.handlings[0].response.headers)

    def test_explicit_on(self):
        mc = self.deproxy.make_request(url=self.url,
                                       handler_function=self.handler2)
        self.assertIn('server', mc.received_response.headers)
        self.assertIn('date', mc.received_response.headers)
        self.assertIn('Server', mc.handlings[0].response.headers)
        self.assertIn('Date', mc.handlings[0].response.headers)

    def test_explicit_off(self):
        mc = self.deproxy.make_request(url=self.url,
                                       handler_function=self.handler3)
        self.assertNotIn('server', mc.received_response.headers)
        self.assertNotIn('date', mc.received_response.headers)
        self.assertNotIn('server', mc.handlings[0].response.headers)
        self.assertNotIn('date', mc.handlings[0].response.headers)
        self.assertNotIn('Server', mc.received_response.headers)
        self.assertNotIn('Date', mc.received_response.headers)
        self.assertNotIn('Server', mc.handlings[0].response.headers)
        self.assertNotIn('Date', mc.handlings[0].response.headers)


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port-base', help='The base port number to use when '
                        'assigning ports to tests. Each test case uses the '
                        'next lower port number than the test case before. '
                        'The default is 9999.', default=9999, type=int)
    parser.add_argument('--print-log', action='store_true',
                        help='Print the log.')
    args = parser.parse_args()

    if args.print_log:
        logging.basicConfig(level=logging.DEBUG,
                            format=('%(asctime)s %(levelname)s:%(name)s:'
                                    '%(funcName)s:'
                                    '%(filename)s(%(lineno)d):'
                                    '%(threadName)s(%(thread)d):%(message)s'))

    global deproxy_port_base
    deproxy_port_base = args.port_base

    unittest.main(argv=[''])

if __name__ == '__main__':
    run()
