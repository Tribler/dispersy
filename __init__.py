import sys

_revision_information = {}

def update_revision_information(url, revision):
    print >> sys.stderr, revision, url
    _revision_information[url] = revision

def get_revision_information():
    return _revision_information

def get_revision():
    return max(_revision_information.itervalues())
