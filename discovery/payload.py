from Tribler.dispersy.payload import Payload, IntroductionRequestPayload

MAXLONG128 = (1 << 1024) - 1
MAXLONG256 = (1 << 2048) - 1


class SimilarityRequest(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, identifier, preference_list):
            assert isinstance(identifier, int), type(identifier)
            assert not preference_list or isinstance(preference_list, list), type(preference_list)
            if preference_list:
                for preference in preference_list:
                    assert isinstance(preference, long), type(preference)

            self._identifier = identifier
            self._preference_list = preference_list

        @property
        def identifier(self):
            return self._identifier

        @property
        def preference_list(self):
            return self._preference_list


class PingPayload(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, identifier):
            assert isinstance(identifier, int), type(identifier)

            super(PingPayload.Implementation, self).__init__(meta)
            self._identifier = identifier

        @property
        def identifier(self):
            return self._identifier


class PongPayload(PingPayload):
    pass
