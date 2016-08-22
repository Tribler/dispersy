from twisted.internet.defer import inlineCallbacks
from .dispersytestclass import DispersyTestFunc
from ..discovery.community import DiscoveryCommunity, BOOTSTRAP_FILE_ENVNAME
from ..discovery.bootstrap import _DEFAULT_ADDRESSES
import os
import time
from ..util import blocking_call_on_reactor_thread


class TestDiscovery(DispersyTestFunc):

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def setUp(self):
        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()
        yield super(TestDiscovery, self).setUp()

    def test_overlap(self):
        def get_preferences():
            return ['0' * 20, '1' * 20]
        self._community.my_preferences = get_preferences

        node,  = self.create_nodes(1)
        node._community.my_preferences = get_preferences

        node.process_packets()
        self._mm.process_packets()
        time.sleep(1)

        assert node._community.is_taste_buddy_mid(self._mm.my_mid)
        assert self._mm._community.is_taste_buddy_mid(node.my_mid)

    def test_introduction(self):
        def get_preferences(node_index):
            return [str(i) * 20 for i in range(node_index, node_index + 2)]

        most_similar = []

        def get_most_similar(orig_method, candidate):
            most_similar.append(orig_method(candidate))
            return most_similar[-1]

        self._community.my_preferences = lambda: get_preferences(0)

        node,  = self.create_nodes(1)
        node._community.my_preferences = lambda: get_preferences(1)

        node.process_packets()
        self._mm.process_packets()
        time.sleep(1)

        assert node._community.is_taste_buddy_mid(self._mm.my_mid)
        assert self._mm._community.is_taste_buddy_mid(node.my_mid)

        other,  = self.create_nodes(1)
        other._community.my_preferences = lambda: get_preferences(2)
        orig_method = other._community.get_most_similar
        other._community.get_most_similar = lambda candidate: get_most_similar(orig_method, candidate)

        other._community.add_discovered_candidate(self._mm.my_candidate)
        other.take_step()

        self._mm.process_packets()
        other.process_packets()
        time.sleep(1)

        # other and mm should not be taste buddies
        assert not other._community.is_taste_buddy_mid(self._mm.my_mid)
        assert not self._mm._community.is_taste_buddy_mid(other.my_mid)

        # other should have requested an introduction to node
        assert most_similar[-1][1] == node.my_mid

    def create_nodes(self, *args, **kwargs):
        return super(TestDiscovery, self).create_nodes(*args, community_class=DiscoveryCommunity, **kwargs)
