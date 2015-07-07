from time import time, sleep

from .dispersytestclass import DispersyTestFunc


class TestBatch(DispersyTestFunc):

    def __init__(self, *args, **kargs):
        super(TestBatch, self).__init__(*args, **kargs)
        self._big_batch_took = 0.0
        self._small_batches_took = 0.0

    def test_one_batch(self):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        messages = [node.create_batched_text("duplicates", i + 10) for i in range(10)]
        other.give_messages(messages, node, cache=True)

        # no messages may be in the database, as they need to be batched
        other.assert_count(messages[0], 0)

        sleep(messages[0].meta.batch.max_window + 1.0)

        # all of the messages must be stored in the database, as batch_window expired
        other.assert_count(messages[0], 10)

    def test_multiple_batch(self):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        messages = [node.create_batched_text("duplicates", i + 10) for i in range(10)]
        for message in messages:
            other.give_message(message, node, cache=True)

            # no messages may be in the database, as they need to be batched
            other.assert_count(message, 0)

        sleep(messages[0].meta.batch.max_window + 1.0)

        # all of the messages must be stored in the database, as batch_window expired
        other.assert_count(messages[0], 10)

    def test_one_big_batch(self, length=1000):
        """
        Test that one big batch of messages is processed correctly.
        Each community is handled in its own batch, hence we can measure performance differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time)
                    for global_time in xrange(10, 10 + length)]

        begin = time()
        other.give_messages(messages, node)
        end = time()
        self._big_batch_took = end - begin

        other.assert_count(messages[0], len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)

    def test_many_small_batches(self, length=1000):
        """
        Test that many small batches of messages are processed correctly.
        Each community is handled in its own batch, hence we can measure performance differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time)
                    for global_time in xrange(10, 10 + length)]

        begin = time()
        for message in messages:
            other.give_message(message, node)
        end = time()
        self._small_batches_took = end - begin

        other.assert_count(messages[0], len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)
