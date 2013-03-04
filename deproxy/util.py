

def try_get_value_case_insensitive(d, key_name):
    """
    Look in a dictionary for a key with the given key_name, without concern
    for case, and return the value of the first key found, or None.
    """
    for name, value in d.items():
        if name.lower() == key_name.lower():
            return value
    return None


def try_add_value_case_insensitive(d, key_name, new_value):
    """
    Look in a dictionary for a key with the given key_name, without concern
    for case. If the key is found, return the associated value. Otherwise, set
    the value to that provided.
    """
    for name, value in d.items():
        if name.lower() == key_name.lower():
            return value
    d[key_name] = new_value
    return new_value


def try_del_key_case_insensitive(d, key_name):
    """
    Look in a dictionary for all keys with the given key_name, without concern
    for case. If found, delete them from the dictionary.
    """
    to_delete = []
    for name, value in d.items():
        if name.lower() == key_name.lower():
            to_delete.append(name)
    for name in to_delete:
        del d[name]
    return (len(to_delete) > 0)


def text_from_file(file):
    """
    If the 'file' parameter is a file-like object, return its contents as a
    string. Otherwise, return the string form of 'file'.
    """
    try:
        s = file.read()
        return s
    except AttributeError:
        return str(file)


def lines_from_file(file):
    """
    If the 'file' parameter is a file-like object, return its contents as a
    list of lines (strings). Otherwise, return the string form of 'file' split
    into lines.
    """
    try:
        s = file.read()
        return s.splitlines()
    except AttributeError:
        return str(file).splitlines()
