#!/usr/bin/python

import sys

import deproxy
import unittest
import threading
import logging
import socket
import argparse


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


class TestRoute(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))
        self.handler = deproxy.route('http', 'github.com', self.deproxy)

    def tearDown(self):
        pass

    def test_route(self):
        mc = self.deproxy.make_request('http://localhost:%i/izrik/deproxy' %
                                       self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestDefaultHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def test_default_handler(self):
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestCustomHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))

    def test_custom_handler(self):
        def custom_handler(request):
            return deproxy.Response(code=606, message="Spoiler",
                                    headers={"Header-Name": "Header-Value"},
                                    body='Snape Kills Dumbledore')
        mc = self.deproxy.make_request('http://localhost:%i/' %
                                       self.deproxy_port,
                                       handler_function=custom_handler)
        self.assertEquals(int(mc.received_response.code), 606)


class TestOrphanedHandlings(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = get_next_deproxy_port()
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost',
                                                    self.deproxy_port))
        self.other_client = deproxy.Deproxy()

    def test_orphaned_handling(self):
        delayed_handler = deproxy.delay_and_then(2, deproxy.default_handler)
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
