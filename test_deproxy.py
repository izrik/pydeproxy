#!/usr/bin/python

import sys

import deproxy
import unittest
import threading
import logging
import socket


deproxy_port_base = 9999

class TestRoute(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = deproxy_port_base - 0
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', self.deproxy_port))
        self.handler = deproxy.route('http', 'github.com', self.deproxy)

    def tearDown(self):
        pass

    def test_route(self):
        mc = self.deproxy.make_request('http://localhost:%i/izrik/deproxy' % self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestDefaultHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = deproxy_port_base - 1
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', self.deproxy_port))

    def test_default_handler(self):
        mc = self.deproxy.make_request('http://localhost:%i/' % self.deproxy_port)
        self.assertEquals(int(mc.received_response.code), 200)


class TestCustomHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = deproxy_port_base - 2
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', self.deproxy_port))

    def test_custom_handler(self):
        def custom_handler(request):
            return deproxy.Response(code=606, message="Spoiler",
                                    headers={"Header-Name": "Header-Value"},
                                    body='Snape Kills Dumbledore')
        mc = self.deproxy.make_request('http://localhost:%i/' % self.deproxy_port,
                                       handler_function=custom_handler)
        self.assertEquals(int(mc.received_response.code), 606)


class TestOrphanedHandlings(unittest.TestCase):
    def setUp(self):
        self.deproxy_port = deproxy_port_base - 3
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', self.deproxy_port))
        self.other_client = deproxy.Deproxy()

    def test_orphaned_handling(self):
        delayed_handler = deproxy.delay_and_then(2, deproxy.default_handler)
        self.long_running_mc = None

        class Helper:
            mc = None

        helper = Helper()

        def other_thread():
            mc = self.deproxy.make_request('http://localhost:%i/' % self.deproxy_port,
                                           handler_function=delayed_handler)
            helper.mc = mc

        t = threading.Thread(target=other_thread)
        t.daemon = True
        t.start()
        self.other_client.make_request('http://localhost:%i/' % self.deproxy_port)
        t.join()
        self.assertEqual(len(helper.mc.orphaned_handlings), 1)


class TestEndpointShutdown(unittest.TestCase):
    def setUp(self):
        self.deproxy_port1 = deproxy_port_base - 4
        self.deproxy_port2 = deproxy_port_base - 5
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
        self.deproxy_port1 = deproxy_port_base - 6
        self.deproxy_port2 = deproxy_port_base - 7
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


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG,
    #                    format=('%(asctime)s %(levelname)s:%(name)s:'
    #                            '%(funcName)s:'
    #                            '%(filename)s(%(lineno)d):'
    #                            '%(threadName)s(%(thread)d):%(message)s'))
    unittest.main()
