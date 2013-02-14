_revision_information = {}

def update_revision_information(url, revision):
    if not (url == "$HeadURL$" and revision == "$Revision$"):
        _revision_information[url[10:-2]] = int(revision[11:-2])

def get_revision_information():
    return _revision_information

def get_revision():
    return max(_revision_information.itervalues())
