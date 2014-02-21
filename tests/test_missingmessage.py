from random import shuffle

from ..logger import get_logger
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestMissingMessage(DispersyTestFunc):

    def _test_with_order(self, batchFUNC):
        """
        NODE generates a few messages and OTHER requests them one at a time.
        """
        node, other = self.create_nodes(2)

        # create messages
        messages = [node.create_full_sync_text("Message #%d" % i, i) for i in xrange(10)]
        batches = batchFUNC(messages)

        for messages in batches:
            global_times = sorted([message.distribution.global_time for message in messages])
            # request messages
            node.give_message(other.create_dispersy_missing_message(node.my_member,), other)
            yield 0.11

            # receive response
            responses = []
            for _ in range(len(messages)):
                _, response = other.receive_message(names=[message.name])
                responses.append(response)

            self.assertEqual(sorted(response.distribution.global_time for response in responses), global_times)

    @call_on_dispersy_thread
    def test_single_request(self):
        def batch(messages):
            return [[message] for message in messages]
        self._test_with_order(batch)

    @call_on_dispersy_thread
    def test_single_request_out_of_order(self):
        def batch(messages):
            shuffle(messages)
            return [[message] for message in messages]
        self._test_with_order(batch)

    @call_on_dispersy_thread
    def test_two_at_a_time(self):
        def batch(messages):
            batches = []
            for i in range(0, len(messages), 2):
                batches.append([messages[i], messages[i + 1]])
            return batches
        self._test_with_order(batch)
