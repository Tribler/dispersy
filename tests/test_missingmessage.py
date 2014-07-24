from random import shuffle

from .dispersytestclass import DispersyTestFunc


class TestMissingMessage(DispersyTestFunc):

    def _test_with_order(self, batchFUNC):
        """
        NODE generates a few messages and OTHER requests them one at a time.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # create messages
        messages = [node.create_full_sync_text("Message #%d" % i, i + 10) for i in xrange(10)]
        node.give_messages(messages, node)

        batches = batchFUNC(messages)

        for messages in batches:
            global_times = sorted([message.distribution.global_time for message in messages])
            # request messages
            node.give_message(other.create_missing_message(node.my_member, global_times), other)

            # receive response
            responses = [response for _, response in other.receive_messages(names=[message.name])]
            self.assertEqual(sorted(response.distribution.global_time for response in responses), global_times)

    def test_single_request(self):
        def batch(messages):
            return [[message] for message in messages]
        self._test_with_order(batch)

    def test_single_request_out_of_order(self):
        def batch(messages):
            shuffle(messages)
            return [[message] for message in messages]
        self._test_with_order(batch)

    def test_two_at_a_time(self):
        def batch(messages):
            batches = []
            for i in range(0, len(messages), 2):
                batches.append([messages[i], messages[i + 1]])
            return batches
        self._test_with_order(batch)
