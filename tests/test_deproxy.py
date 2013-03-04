#!/usr/bin/python

import sys

sys.path.append('.')
sys.path.append('..')

import deproxy
import unittest


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


def custom_handler(request):
    return deproxy.Response(code=606, message="Spoiler",
                            headers={"Header-Name": "Header-Value"},
                            body='Snape Kills Dumbledore')


class TestCustomHandler(unittest.TestCase):
    def setUp(self):
        self.deproxy = deproxy.Deproxy()
        self.end_point = self.deproxy.add_endpoint(('localhost', 9997))

    def test_default_handler(self):
        mc = self.deproxy.make_request('http://localhost:9997/',
                                       handler_function=custom_handler)
        self.assertEquals(int(mc.received_response.code), 606)


if __name__ == '__main__':
    unittest.main()
