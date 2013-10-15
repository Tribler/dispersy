from os import path
from socket import gethostbyname
from threading import Thread, Lock, Event

from .candidate import BootstrapCandidate
from .logger import get_logger
logger = get_logger(__name__)

_trackers = [(u"dispersy1.tribler.org", 6421),
             (u"dispersy2.tribler.org", 6422),
             (u"dispersy3.tribler.org", 6423),
             (u"dispersy4.tribler.org", 6424),
             (u"dispersy5.tribler.org", 6425),
             (u"dispersy6.tribler.org", 6426),
             (u"dispersy7.tribler.org", 6427),
             (u"dispersy8.tribler.org", 6428),

             (u"dispersy1b.tribler.org", 6421),
             (u"dispersy2b.tribler.org", 6422),
             (u"dispersy3b.tribler.org", 6423),
             (u"dispersy4b.tribler.org", 6424),
             (u"dispersy5b.tribler.org", 6425),
             (u"dispersy6b.tribler.org", 6426),
             (u"dispersy7b.tribler.org", 6427),
             (u"dispersy8b.tribler.org", 6428)]


def get_bootstrap_hosts(working_directory):
    """
    Reads WORKING_DIRECTORY/bootstraptribler.txt and returns the hosts therein, otherwise it
    returns _TRACKERS.
    """
    trackers = []
    filename = path.join(working_directory, "bootstraptribler.txt")
    try:
        for line in open(filename, "r"):
            line = line.strip()
            if not line.startswith("#"):
                host, port = line.split()
                trackers.append((host.decode("UTF-8"), int(port)))
    except:
        pass

    if trackers:
        return trackers
    else:
        return _trackers


def get_bootstrap_candidates(dispersy, timeout=1.0):
    """
    Returns a list with all known bootstrap peers.

    Bootstrap peers are retrieved from WORKING_DIRECTORY/bootstraptribler.txt if it exits.
    Otherwise it is created using the trackers defined in _TRACKERS.

    Each bootstrap peer gives either None or a Candidate.  None values can be caused by
    malfunctioning DNS.
    """
    assert isinstance(timeout, float), type(timeout)
    assert timeout > 0.0, timeout

    def gethostbyname_in_parallel():
        for host, port in hosts:
            if event.is_set():
                # timeout
                break

            try:
                candidate = BootstrapCandidate((gethostbyname(host), port), False)

            except:
                logger.exception("unable to obtain BootstrapCandidate(%s, %d)", host, port)
                candidate = None

            with lock:
                results.append(candidate)

        # indicate results are ready
        event.set()

    lock = Lock()
    event = Event()
    results = []
    hosts = get_bootstrap_hosts(dispersy.working_directory)
    logger.debug("obtaining %d BootstrapCandidates", len(hosts))

    # start thread
    thread = Thread(target=gethostbyname_in_parallel, name="Get-Bootstrap-Candidates")
    thread.damon = True
    thread.start()

    # wait for results
    event.wait(timeout)
    event.set()

    # return results
    with lock:
        logger.debug("returning %d/%d BootstrapCandidates", len([result for result in results if result]), len(hosts))
        return results[:]
