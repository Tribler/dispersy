import logging


logger = logging.getLogger(__name__)

# Remove the limited history observer log
# When running trackers that are using Twisted logging for a long time, this observer will cause memory issues
# See http://twistedmatrix.com/trac/ticket/7841 for more information about this issue


def clean_twisted_observers(publisher=None):
    try:
        from twisted.logger import LogPublisher, LimitedHistoryLogObserver, globalLogPublisher
        if not publisher:
            publisher = globalLogPublisher
    except ImportError:
        logger.debug("Running an older version of twisted, no need to clean the observers")
        return

    logger.debug("Looking for rogue observers in %r", publisher._observers)

    for observer in publisher._observers:
        if isinstance(observer, LogPublisher):
            clean_twisted_observers(observer)

        elif isinstance(observer, LimitedHistoryLogObserver):
            publisher.removeObserver(observer)
            logger.debug("Removing observer %s", observer)

        else:
            logger.debug("Leaving alone observer %s", observer)
