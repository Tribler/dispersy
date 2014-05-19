from ..payload import Payload, IntroductionRequestPayload


class SimilarityRequestPayload(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, identifier, lan_address, wan_address, connection_type, preference_list):
            assert isinstance(identifier, int), type(identifier)
            assert not preference_list or isinstance(preference_list, (list, tuple)), type(preference_list)

            for preference in preference_list:
                assert isinstance(preference, str), type(preference)
                assert len(preference) == 20, len(preference)

            self._identifier = identifier
            self._preference_list = preference_list
            self._lan_address = lan_address
            self._wan_address = wan_address
            self._connection_type = connection_type

        @property
        def identifier(self):
            return self._identifier

        @property
        def lan_address(self):
            return self._lan_address

        @property
        def wan_address(self):
            return self._wan_address

        @property
        def connection_type(self):
            return self._connection_type

        @property
        def preference_list(self):
            return self._preference_list


class SimilarityResponsePayload(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, identifier, preference_list, tb_overlap):
            assert isinstance(identifier, int), type(identifier)
            assert not preference_list or isinstance(preference_list, (list, tuple)), type(preference_list)
            assert not tb_overlap or isinstance(tb_overlap, list), type(tb_overlap)

            for preference in preference_list:
                assert isinstance(preference, str), type(preference)
                assert len(preference) == 20, len(preference)

            for bitfield in tb_overlap:
                assert isinstance(bitfield, tuple), type(bitfield)
                assert isinstance(bitfield[0], str), type(bitfield[0])
                assert isinstance(bitfield[1], int), type(bitfield[1])

            self._identifier = identifier
            self._preference_list = preference_list
            self._tb_overlap = tb_overlap

        @property
        def identifier(self):
            return self._identifier

        @property
        def preference_list(self):
            return self._preference_list

        @property
        def tb_overlap(self):
            return self._tb_overlap


class ExtendedIntroPayload(IntroductionRequestPayload):
    class Implementation(IntroductionRequestPayload.Implementation):

        def __init__(self, meta, destination_address, source_lan_address, source_wan_address, advice, connection_type, sync, identifier, introduce_me_to=None):
            IntroductionRequestPayload.Implementation.__init__(
                self, meta, destination_address, source_lan_address, source_wan_address, advice, connection_type, sync, identifier)
            if introduce_me_to:
                assert isinstance(introduce_me_to, str), 'introduce_me_to should be str'
                assert len(introduce_me_to) == 20, len(introduce_me_to)

            self._introduce_me_to = introduce_me_to

        def set_introduce_me_to(self, introduce_me_to):
            self._introduce_me_to = introduce_me_to

        @property
        def introduce_me_to(self):
            return self._introduce_me_to


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

