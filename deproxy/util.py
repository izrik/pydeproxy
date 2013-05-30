
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


def read_body_from_stream(stream, headers):
    if ('Transfer-Encoding' in headers and
            headers['Transfer-Encoding'] != 'identity'):
        # 2
        raise NotImplementedError
    elif 'Content-Length' in headers:
        # 3
        length = int(headers['Content-Length'])
        body = stream.read(length)
    elif False:
        # multipart/byteranges ?
        raise NotImplementedError
    else:
        # there is no body
        body = None
    return body
