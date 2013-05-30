

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
