.. :changelog:

History
-------

0.6 (2013-05-30)
++++++++++++++++

- Added a class, ``HeaderCollection``, to hold request and response headers
  instead of using a ``dict``. The new class is a hybrid of a dictionary and a
  list of tuples. It supports case-insensitive lookup and storing multiple
  values for headers with the same name.
- Updated reading of simple message bodies. It doesn't yet support chunked
  transfers or encodings, but it's far more useful.
- Re-organized the codebase from a multi-file package into a single module.

0.5 (2013-05-16)
++++++++++++++++

- Fixed the logic when adding default headers so that they are recorded in the
  handlings as well.

0.4 (2013-05-16)
++++++++++++++++

- Added option to ``make_request`` to not add default request headers
- Added option to handler functions to not add default response headers

