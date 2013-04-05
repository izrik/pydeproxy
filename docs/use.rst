===============
 Using Deproxy
===============

To use deproxy in your unit tests:

  1. In the TestCase's setUp method, create a Deproxy object and endpoint(s), and configure your proxy to forward requests to the endpoint's port.
  2. In the actual test method, use the make_request method to send a request to the proxy, and get a message chain back.
  3. Still in the text method, make assertions against the returned message chain.
  4. In the tearDown method, shutdown the Deproxy object by calling shutdown_all_endpoints.

An example::

    import unittest
    import deproxy

    class TestTheProxy(unittest.TestCase):

        def setUp(self):
            self.deproxy = deproxy.Deproxy()
            self.end_point = self.deproxy.add_endpoint(('localhost', 9999))

            # Set up the proxy to listen on port 8080, forwarding requests to
            # localhost:9999, to add an "X-Request" header to requests and an
            # "X-Response" header to responses.

        def test_the_proxy(self):
            mc = self.deproxy.make_request(method='GET',
                                           url='http://localhost:8080/')

            self.assertEqual(mc.received_response.code, '200',
                             msg='Must return 200')

            self.assertEqual(len(mc.handlings), 1,
                             msg='The request must reach the origin server '
                                 'exactly once.')

            self.assertTrue('X-Request' in mc.handlings[0].request.headers,
                            msg="No X-Request header in forwarded request.")

            self.assertTrue('X-Response' in mc.received_response.headers,
                            msg="No X-Response header in forwarded response.")

        def tearDown(self):
            #shut down the proxy, if needed

            if self.deproxy is not None:
                self.deproxy.shutdown_all_endpoints()

    if __name__ == '__main__':
        unittest.main()

