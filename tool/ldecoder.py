from bz2 import BZ2File
from os import walk
from os.path import join
from traceback import print_exc
import sys


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
            return split + length + 1, stream[split + 1:split + length+1]
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])


def _decode_hex(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split + 1:split + length+1].decode("HEX")
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])


def _decode_unicode(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split + 1:split + length+1].decode("UTF8")
        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])


def _decode_Hex(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] == ":":
            length = int(stream[offset:split])
            return split + length + 1, stream[split + 1:split + length+1].decode("HEX").decode("UTF8")
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
    if stream[offset:offset + 4] == "True":
        return offset + 4, True
    elif stream[offset:offset + 5] == "False":
        return offset + 5, False
    else:
        raise ValueError()


def _decode_none(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    if stream[offset:offset + 4] == "None":
        return offset + 4, None
    else:
        raise ValueError("Expected None")


def _decode_tuple(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split + 1] == "(":
                raise ValueError("Expected '('", stream[split + 1])
            offset = split + 2  # compensate for ':('
            l = []
            if length:
                for index in range(length):
                    offset, value = _decode(offset, stream)
                    l.append(value)

                    if index < length and stream[offset] == "," and stream[offset + 1] == " ":
                        offset += 2  # compensate for ', '
                    elif index == length - 1 and stream[offset] == ")":
                        offset += 1  # compensate for ')'
                    else:
                        raise ValueError()
            else:
                if not stream[offset] == ")":
                    raise ValueError("Expected ')'", stream[split + 1])
                offset += 1  # compensate for ')'

            return offset, tuple(l)

        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])


def _decode_list(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split + 1] == "[":
                raise ValueError("Expected '['", stream[split + 1])
            offset = split + 2  # compensate for ':['
            l = []
            if length:
                for index in range(length):
                    offset, value = _decode(offset, stream)
                    l.append(value)

                    if index < length and stream[offset] == "," and stream[offset + 1] == " ":
                        offset += 2  # compensate for ', '
                    elif index == length - 1 and stream[offset] == "]":
                        offset += 1  # compensate for ']'
                    else:
                        raise ValueError()
            else:
                if not stream[offset] == "]":
                    raise ValueError("Expected ']'", stream[split + 1])
                offset += 1  # compensate for ']'

            return offset, l

        elif not stream[split] in "1234567890":
            raise ValueError("Can not decode string length", stream[split])


def _decode_dict(offset, stream):
    assert isinstance(offset, (int, long))
    assert isinstance(stream, str)
    for split in _counter(offset):
        if stream[split] in ":":
            length = int(stream[offset:split])
            if not stream[split + 1] == "{":
                raise ValueError("Expected '{'", stream[split + 1])
            offset = split + 2  # compensate for ':{'
            d = {}
            for index in range(length):
                offset, key = _decode(offset, stream)
                if key in d:
                    raise ValueError("Duplicate map entry", key)
                if not stream[offset] == ":":
                    raise ValueError("Expected ':'", stream[offset])
                offset += 1  # compensate for ':'
                offset, value = _decode(offset, stream)
                d[key] = value

                if index < length and stream[offset] == "," and stream[offset + 1] == " ":
                    offset += 2  # compensate for ', '
                elif index == length - 1 and stream[offset] == "}":
                    offset += 1  # compensate for '}'
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


def _parse(handle, interests, raise_exceptions=True):
    assert isinstance(interests, set)
    for lineno, stream in zip(_counter(1), handle):
        if stream.startswith("#"):
            continue

        try:
            offset = _ignore_seperator(17, stream)
            if not stream[offset] == "s":
                raise ValueError("Expected a string encoded message")
            offset, message = _decode_str(offset + 1, stream)

            if not interests or message in interests:
                stamp = float(stream[:17])
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
        except Exception as e:
            if raise_exceptions:
                raise ValueError("Cannot read line", str(e), "on line", lineno)
            else:
                print >> sys.stderr, "Cannot read line", str(e), "on line", lineno
                print_exc()


def bz2parse(filename, interests=(), raise_exceptions = True):
    """
    Parse the content of bz2 encoded FILENAME.

    Yields a (LINENO, TIMESTAMP, MESSAGE, KARGS) tuple for each line in the file.
    """
    assert isinstance(filename, (str, unicode))
    assert isinstance(interests, (tuple, list, set))
    assert all(isinstance(interest, str) for interest in interests)
    return _parse(BZ2File(filename, "r"), set(interests), raise_exceptions)


def parse(filename, interests=(), raise_exceptions = True):
    """
    Parse the content of FILENAME.

    Yields a (LINENO, TIMESTAMP, MESSAGE, KARGS) tuple for each line in
    the file.
    """
    assert isinstance(filename, (str, unicode))
    assert isinstance(interests, (tuple, list, set))
    assert all(isinstance(interest, str) for interest in interests)
    return _parse(open(filename, "r"), set(interests), raise_exceptions)


def parselast(filename, interests=(), raise_exceptions = True, chars = 2048):
    """
    Parse the last X chars from the content of FILENAME.

    Yields a (LINENO, TIMESTAMP, MESSAGE, KARGS) tuple for each line in
    the file.
    """
    assert isinstance(filename, (str, unicode))
    assert isinstance(interests, (tuple, list, set))
    assert all(isinstance(interest, str) for interest in interests)

    # From http://stackoverflow.com/a/260352
    f = open(filename, "r")
    f.seek(0, 2)           # Seek @ EOF
    fsize = f.tell()        # Get Size
    f.seek(max(fsize - chars, 0), 0)  # Set pos @ last n chars

    # skip broken line
    f.readline()

    lines = f.readlines()
    lines.reverse()
    return _parse(lines, set(interests), raise_exceptions)


class NextFile(Exception):
    pass


class Parser(object):

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.filename = ""
        self.progress = 0
        self.mapping = {}

    def mapto(self, func, *messages):
        for message in messages:
            if not message in self.mapping:
                self.mapping[message] = []
            self.mapping[message].append(func)

    def unknown(self, _, name, **kargs):
        if self.verbose:
            print "# unknown log entry '%s'" % name, "[%s]" % ", ".join(kargs.iterkeys())
        self.mapping[name] = [self.ignore]

    def ignore(self, stamp, _, **kargs):
        pass

    def start_parser(self, filename):
        """Called once before starting to parse FILENAME"""
        self.filename = filename
        self.progress += 1

    def stop_parser(self, lineno):
        """Called once when finished parsing LINENO lines"""
        if self.verbose:
            print "#", self.progress, self.filename, "->", lineno, "lines"

    def parse_file(self, filename, bzip2=False, unknown=False):
        parser = bz2parse if bzip2 else parse
        interests = () if unknown else set(self.mapping.keys())
        unknown = [self.unknown]

        self.start_parser(filename)
        lineno = 0
        try:
            for lineno, timestamp, name, kargs in parser(filename, interests):
                for func in self.mapping.get(name, unknown):
                    func(timestamp, name, **kargs)
        except NextFile:
            pass
        self.stop_parser(lineno)

    def parse_directory(self, directory, filename, bzip2=False, unknown=False):
        parser = bz2parse if bzip2 else parse
        interests = () if unknown else set(self.mapping.keys())
        unknown = [self.unknown]

        for directory, _, filenames in walk(directory):
            if filename in filenames:
                filepath = join(directory, filename)

                self.start_parser(filepath)
                lineno = 0
                try:
                    for lineno, timestamp, name, kargs in parser(filepath, interests):
                        for func in self.mapping.get(name, unknown):
                            func(timestamp, name, **kargs)
                except NextFile:
                    pass
                self.stop_parser(lineno)

_valid_key_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"
_decode_mapping = {"s": _decode_str,
                   "h": _decode_hex,
                   "u": _decode_unicode,
                   "H": _decode_Hex,
                   "i": _decode_int,
                   "j": _decode_long,
                   "f": _decode_float,
                   "b": _decode_boolean,
                   "n": _decode_none,
                   "t": _decode_tuple,
                   "l": _decode_list,
                   "m": _decode_dict}
