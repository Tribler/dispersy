#!/usr/bin/python

from bz2 import BZ2File
from datetime import datetime

class NotInterested(Exception):
    pass

def _counter(start):
    assert isinstance(start, (int, long))
    count = start
    while True:
        yield count
        count += 1

def _ignore_seperator(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for start in _counter(offset):
        if not stream[start] == " ":
            return start
    raise ValueError()

def _decode_str(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split+1:split+length+1]
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_hex(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split+1:split+length+1].decode("HEX")
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_unicode(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split+1:split+length+1].decode("UTF8")
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_Hex(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split+1:split+length+1].decode("HEX").decode("UTF8")
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_int(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if not stream[split] in "1234567890-":
            return split, int(stream[offset:split])

def _decode_long(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if not stream[split] in "1234567890-":
            return split, long(stream[offset:split])

def _decode_float(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if not stream[split] in "1234567890+-.e":
            return split, float(stream[offset:split])

def _decode_boolean(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    if stream[offset:offset+4] == "True":
        return offset+4, True
    elif stream[offset:offset+5] == "False":
        return offset+5, False
    else:
        raise ValueError()

def _decode_none(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    if stream[offset:offset+4] == "None":
        return offset+4, None
    else:
        raise ValueError("Expected None")

def _decode_tuple(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split+1] == "(":
                raise ValueError("Expected '('", stream[split+1])
            offset = split + 2 # compensate for ':('
            l = []
            if length:
                for index in range(length):
                    offset, value = _decode(offset, stream)
                    l.append(value)

                    if index < length and stream[offset] == "," and stream[offset+1] == " ":
                        offset += 2 # compensate for ', '
                    elif index == length - 1 and stream[offset] == ")":
                        offset += 1 # compensate for ')'
                    else:
                        raise ValueError()
            else:
                if not stream[offset] == ")":
                    raise ValueError("Expected ')'", stream[split+1])
                offset += 1 # compensate for ')'

            return offset, tuple(l)

        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_list(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split+1] == "[":
                raise ValueError("Expected '['", stream[split+1])
            offset = split + 2 # compensate for ':['
            l = []
            if length:
                for index in range(length):
                    offset, value = _decode(offset, stream)
                    l.append(value)

                    if index < length and stream[offset] == "," and stream[offset+1] == " ":
                        offset += 2 # compensate for ', '
                    elif index == length - 1 and stream[offset] == "]":
                        offset += 1 # compensate for ']'
                    else:
                        raise ValueError()
            else:
                if not stream[offset] == "]":
                    raise ValueError("Expected ']'", stream[split+1])
                offset += 1 # compensate for ']'

            return offset, l

        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode_dict(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split+1] == "{":
                raise ValueError("Expected '{'", stream[split+1])
            offset = split + 2 # compensate for ':{'
            d = {}
            for index in range(length):
                offset, key = _decode(offset, stream)
                if key in d:
                    raise ValueError("Duplicate map entry", key)
                if not stream[offset] == ":":
                    raise ValueError("Expected ':'", stream[offset])
                offset += 1 # compensate for ':'
                offset, value = _decode(offset, stream)
                d[key] = value

                if index < length and stream[offset] == "," and stream[offset+1] == " ":
                    offset += 2 # compensate for ', '
                elif index == length - 1 and stream[offset] == "}":
                    offset += 1 # compensate for '}'
                else:
                    raise ValueError()

            return offset, d

        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])

def _decode(offset, stream):
    if stream[offset] in _decode_mapping:
        return _decode_mapping[stream[offset]](offset + 1, stream)
    else:
        raise ValueError("Can not decode {0}".format(stream[offset]))

def _parse(handle, interests):
    assert isinstance(interests, set)
    for lineno, stream in zip(_counter(1), handle):
        if stream.startswith("#"):
            continue

        offset = _ignore_seperator(21, stream)
        if not stream[offset] == "s":
            raise ValueError("Expected a string encoded message")
        offset, message = _decode_str(offset+1, stream)

        try:
            if not interests or message in interests:
                stamp = datetime.strptime(stream[:21], "%Y%m%d%H%M%S.f")
                kargs = {}
                while offset < len(stream) - 1:
                    offset = _ignore_seperator(offset, stream)
                    for split in _counter(offset):
                        if stream[split] == ":":
                            key = stream[offset:split].strip()
                            offset, value = _decode(split + 1, stream)
                            kargs[key] = value
                            break

                        elif not stream[split] in _valid_key_chars:
                            raise ValueError("Can not decode character", stream[split], "on line", lineno, "offset", offset)

                yield lineno, stamp, message, kargs
        except Exception, e:
            raise ValueError("Cannot read line", str(e), "on line", lineno)

def bz2parse(filename, interests=()):
    """
    Parse the content of bz2 encoded FILENAME.

    Yields a (LINENO, DATETIME, MESSAGE, KARGS) tuple for each line in the file.
    """
    assert isinstance(filename, (str, unicode))
    assert isinstance(interests, (tuple, list, set))
    assert all(isinstance(interest, str) for interest in interests)
    return _parse(BZ2File(filename, "r"), set(interests))

def parse(filename, interests=()):
    """
    Parse the content of FILENAME.

    Yields a (LINENO, DATETIME, MESSAGE, KARGS) tuple for each line in
    the file.
    """
    assert isinstance(filename, (str, unicode))
    assert isinstance(interests, (tuple, list, set))
    assert all(isinstance(interest, str) for interest in interests)
    return _parse(open(filename, "r"), set(interests))

_valid_key_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"
_decode_mapping = {"s":_decode_str,
                   "h":_decode_hex,
                   "u":_decode_unicode,
                   "H":_decode_Hex,
                   "i":_decode_int,
                   "j":_decode_long,
                   "f":_decode_float,
                   "b":_decode_boolean,
                   "n":_decode_none,
                   "t":_decode_tuple,
                   "l":_decode_list,
                   "m":_decode_dict}
