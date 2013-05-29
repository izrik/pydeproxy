
class HeaderCollection(object):
    """
    A collection class for HTTP Headers. This class combines aspects of a list
    and a dict. Lookup is always case-insenitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self):
        self.headers = []

    def __contains__(self, item):
        item = item.lower()
        for header in self.headers:
            if header[0].lower() == item:
                return True
        return False

    def __len__(self):
        return self.headers.__len__()

    def __getitem__(self, key):
        key = key.lower()
        for header in self.headers:
            if header[0].lower() == key:
                return header[1]

    def __setitem__(self, key, value):
        lower = key.lower()
        for i, header in enumerate(self.headers):
            if header[0].lower() == lower:
                headers[i] = (header[0], value)
                return
        else:
            self.add(key, value)

    def __delitem__(self, key):
        self.delete_all(name=key)

    def __iter__(self):
        return self.iterkeys()

    def add(self, name, value):
        self.headers.append((name,value,))

    def find_all(self, name):
        name = name.lower()
        for header in self.headers:
            if header[0].lower() == name:
                yield header[1]

    def delete_all(self, name):
        lower = key.lower()
        self.headers = [ header for header in self.headers
                        if header[0].lower() != lower ]

    def iterkeys(self):
        for header in self.headers:
            yield header[0]

    def itervalues(self):
        for header in self.headers:
            yield header[1]

    def iteritems(self):
        for header in self.headers:
            yield header

    def keys(self):
        return [key for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def clear(self):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError

    @classmethod
    def from_keys(cls, seq, value=None):
        raise NotImplementedError

    def get(self, key, default=None):
        raise NotImplementedError

    def has_key(self, key):
        raise NotImplementedError

    def pop(self, key, default=None):
        raise NotImplementedError

    def popitem(self):
        raise NotImplementedError

    def setdefault(self, key, default=None):
        raise NotImplementedError

    def update(self, other=None, **kwargs):
        raise NotImplementedError

    def viewitems(self):
        raise NotImplementedError

    def viewkeys(self):
        raise NotImplementedError

    def viewvalues(self):
        raise NotImplementedError
