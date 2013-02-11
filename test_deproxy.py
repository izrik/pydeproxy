#!/usr/bin/python

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


if __name__ == '__main__':
    unittest.main()
