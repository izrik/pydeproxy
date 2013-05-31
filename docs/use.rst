===============
 Using Deproxy
===============

To use deproxy in your unit tests:

  1. In the TestCase's setUp method, create a Deproxy object and endpoint(s), and configure your proxy to forward requests to the endpoint's port.
  2. In the actual test method, use the make_request method to send a request to the proxy, and get a message chain back.
  3. Still in the text method, make assertions against the returned message chain.
  4. In the tearDown method, shutdown the Deproxy object by calling shutdown_all_endpoints.

Here's a code example of a unit test that tests the fictional the_proxy module::

    import unittest
    import deproxy
    import the_proxy

    class TestTheProxy(unittest.TestCase):

        def setUp(self):
            self.deproxy = deproxy.Deproxy()
            self.end_point = self.deproxy.add_endpoint(port=9999)

            # Set up the proxy to listen on port 8080, forwarding requests to
            # localhost:9999, to add an "X-Request" header to requests and an
            # "X-Response" header to responses.
            self.the_proxy = the_proxy.TheProxy()
            self.the_proxy.port = 8080
            self.the_proxy.target_hostname = 'localhost'
            self.the_proxy.target_port = 9999
            self.the_proxy.request_ops.add(
                the_proxy.add_header(name='X-Request',
                                     value='This is a request'))
            self.the_proxy.response_ops.add(
                the_proxy.add_header(name='X-Response',
                                     value='This is a response'))

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
            if self.the_proxy is not None:
                self.the_proxy.shutdown()
            if self.deproxy is not None:
                self.deproxy.shutdown_all_endpoints()

    if __name__ == '__main__':
        unittest.main()

