from .logger import get_logger
from .requestcache import NumberCache

logger = get_logger(__name__)

class SignatureRequestCache(NumberCache):

    def __init__(self, request_cache, members, response_func, response_args, timeout):
        super(SignatureRequestCache, self).__init__(request_cache, u"signature-request")
        self.request = None
        # MEMBERS is a list containing all the members that should add their signature.  currently
        # we only support double signed messages, hence MEMBERS contains only a single Member
        # instance.
        self.members = members
        self.response_func = response_func
        self.response_args = response_args
        self._timeout_delay = timeout

    @property
    def timeout_delay(self):
        return self._timeout_delay

    def on_timeout(self):
        logger.debug("signature timeout")
        self.response_func(self, None, True, *self.response_args)


class IntroductionRequestCache(NumberCache):

    @property
    def timeout_delay(self):
        # we will accept the response at most 10.5 seconds after our request
        return 10.5

    def __init__(self, community, helper_candidate):
        super(IntroductionRequestCache, self).__init__(community.request_cache, u"introduction-request")
        self.community = community
        self.helper_candidate = helper_candidate
        self.response_candidate = None
        self.puncture_candidate = None
        self._introduction_response_received = False
        self._puncture_received = False

    def on_timeout(self):
        if not self._introduction_response_received:
            # helper_candidate did not respond to a request message in this
            # community.  The obsolete candidates will be removed by the
            # dispersy_get_walk_candidate() in community.

            logger.debug("walker timeout for %s", self.helper_candidate)

            self.community.dispersy.statistics.dict_inc(self.community.dispersy.statistics.walk_fail, self.helper_candidate.sock_addr)

            # set the walk repsonse to be invalid
            self.helper_candidate.walk_response(-1.0)

    def _check_if_both_received(self):
        if self._introduction_response_received and self._puncture_received:
            self.community.request_cache.pop(self.identifier)

    def on_introduction_response(self):
        self._introduction_response_received = True
        self._check_if_both_received()

    def on_puncture(self):
        self._puncture_received = True
        self._check_if_both_received()
