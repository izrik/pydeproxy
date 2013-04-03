#!/usr/bin/python

import sys

sys.path.append('.')
sys.path.append('..')

import deproxy
import unittest
import threading
import logging


class TestRoute(unittest.TestCase):
    def setUp(self):
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', 9999))
        self.handler = deproxy.route('http', 'github.com', self.deproxy)

    def tearDown(self):
        pass

    def test_route(self):
        mc = self.deproxy.make_request('http://localhost:9999/izrik/deproxy')
        self.assertEquals(int(mc.received_response.code), 200)


class TestDefaultHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', 9998))

    def test_default_handler(self):
        mc = self.deproxy.make_request('http://localhost:9998/')
        self.assertEquals(int(mc.received_response.code), 200)


class TestCustomHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', 9997))

    def test_custom_handler(self):
        def custom_handler(request):
            return deproxy.Response(code=606, message="Spoiler",
                                    headers={"Header-Name": "Header-Value"},
                                    body='Snape Kills Dumbledore')
        mc = self.deproxy.make_request('http://localhost:9997/',
                                       handler_function=custom_handler)
        self.assertEquals(int(mc.received_response.code), 606)


class TestOrphanedHandlings(unittest.TestCase):
    def setUp(self):
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', 9996))
        self.other_client = deproxy.Deproxy()

    def test_orphaned_handling(self):
        delayed_handler = deproxy.delay_and_then(2, deproxy.default_handler)
        self.long_running_mc = None

        class Helper:
            mc = None

        helper = Helper()

        def other_thread():
            mc = self.deproxy.make_request('http://localhost:9996/',
                                           handler_function=delayed_handler)
            helper.mc = mc

        t = threading.Thread(target=other_thread)
        t.daemon = True
        t.start()
        self.other_client.make_request('http://localhost:9996/')
        t.join()
        self.assertEqual(len(helper.mc.orphaned_handlings), 1)

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG,
    #                    format=('%(asctime)s %(levelname)s:%(name)s:'
    #                            '%(funcName)s:'
    #                            '%(filename)s(%(lineno)d):'
    #                            '%(threadName)s(%(thread)d):%(message)s'))
    unittest.main()
