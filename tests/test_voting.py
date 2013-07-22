from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread

class TestVoting(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_symmetric_vote(self):
        c = DebugCommunity.create_community(self._dispersy, self._my_member)

        for i in range(2):
            address = ("127.0.0.2", i + 1)
            candidate = c.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("127.0.0.1", i + 1), candidate)

        assert self._dispersy._connection_type == u"symmetric-NAT"

if __name__ == "__main__":
    unittest.main()
