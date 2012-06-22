import sys

_revision_information = {}

def update_revision_information(url, revision):
    print >> sys.stderr, int(revision[11:-2]), url[10:-2]
    _revision_information[url] = revision

def get_revision_information():
    return _revision_information

def get_revision():
    return max(_revision_information.itervalues())
