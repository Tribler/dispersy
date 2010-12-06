from hashlib import sha1

from Meta import MetaObject

class Payload(MetaObject):
    class Implementation(MetaObject.Implementation):
        @property
        def type(self):
            return self._meta.type

        @property
        def footprint(self):
            raise NotImplementedError()

    @classmethod
    def get_static_type(cls):
        """
        The subclasses Authorize, Revoke, and Permit are sometimes
        used to indicate to what type of payload something applied; In
        this case this method can be used to get the corresponding
        type: u'authorize', u'revoke', and u'permit'.
        """
        return {Authorize:u"authorize", Revoke:u"revoke", Permit:u"permit"}[cls]

    @property
    def type(self):
        """
        Returns u'authorize', u'revoke', and u'permit' for Authorize,
        Revoke, and Permit instances respectively.
        """
        raise NotImplementedError()

    def generate_footprint(self):
        raise NotImplementedError()

    def __str__(self):
        return "<{0.__class__.__name__} {0.type}>".format(self)

class Authorize(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, to, payload):
            """
            User TO is given permission to use PAYLOAD.

            TO is the member that is allowed to use PAYLOAD.
            PAYLOAD is the kind of payload that is allowed {Authorize, Revoke, Permit}.
            """
            if __debug__:
                from Member import Member
                from Payload import Payload
                assert isinstance(to, Member)
                assert issubclass(payload, Payload)
            super(Authorize.Implementation, self).__init__(meta)
            self._to = to
            self._payload = payload

        @property
        def type(self):
            return u"authorize"

        @property
        def footprint(self):
            return "Authorize"

        @property
        def to(self):
            return self._to

        @property
        def payload(self):
            return self._payload

    def generate_footprint(self):
        return "Authorize"

class Revoke(Payload):
    class Implementation(Payload.Implementation):
        def __init__(self, meta, to, payload):
            """
            User TO is no longer allowed to use PAYLOAD.

            TO is the Member that will be revoked.
            PAYLOAD is the payload type that is revoked {Authorize, Revoke, Permit}.
            """
            if __debug__:
                from Member import Member
                from Payload import Payload
                assert isinstance(to, Member)
                assert issubclass(payload, Payload)
            super(Revoke.Implementation, self).__init__(meta)
            self._to = to
            self._payload = payload

        @property
        def type(self):
            return u"revoke"

        @property
        def footprint(self):
            return "Revoke"

        @property
        def to(self):
            return self._to

        @property
        def payload(self):
            return self._payload

    def generate_footprint(self):
        return "Revoke"

class Permit(Payload):
    class Implementation(Payload.Implementation):
        @property
        def type(self):
            return u"permit"

        @property
        def footprint(self):
            return "Permit"

    def generate_footprint(self):
        return "Permit"

class MissingSequencePayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, member, message, missing_low, missing_high):
            """
            We are missing messages of type MESSAGE signed by USER.  We
            are missing sequence numbers >= missing_low to <=
            missing_high.
            """
            if __debug__:
                from Member import Member
                from Message import Message
            assert isinstance(member, Member)
            assert isinstance(message, Message)
            assert isinstance(missing_low, (int, long))
            assert isinstance(missing_high, (int, long))
            assert 0 < missing_low <= missing_high
            super(MissingSequencePayload.Implementation, self).__init__(meta)
            self._member = member
            self._message = message
            self._missing_low = missing_low
            self._missing_high = missing_high

        @property
        def member(self):
            return self._member

        @property
        def message(self):
            return self._message

        @property
        def missing_low(self):
            return self._missing_low

        @property
        def missing_high(self):
            return self._missing_high

class RoutingPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, source_address, destination_address):
            assert isinstance(source_address, tuple)
            assert len(source_address) == 2
            assert isinstance(source_address[0], str)
            assert isinstance(source_address[1], int)
            assert isinstance(destination_address, tuple)
            assert len(destination_address) == 2
            assert isinstance(destination_address[0], str)
            assert isinstance(destination_address[1], int)
            super(RoutingPayload.Implementation, self).__init__(meta)
            self._source_address = source_address
            self._destination_address = destination_address

        @property
        def source_address(self):
            return self._source_address

        @property
        def destination_address(self):
            return self._destination_address

class RoutingRequestPayload(RoutingPayload):
    class Implementation(RoutingPayload.Implementation):
        pass

class RoutingResponsePayload(RoutingPayload):
    class Implementation(RoutingPayload.Implementation):
        pass

class SignatureRequestPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, message):
            super(SignatureRequestPayload.Implementation, self).__init__(meta)
            self._message = message

        @property
        def message(self):
            return self._message

class SignatureResponsePayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, identifier, signature):
            assert isinstance(identifier, str)
            assert len(identifier) == 20
            super(SignatureResponsePayload.Implementation, self).__init__(meta)
            self._identifier = identifier
            self._signature = signature

        @property
        def identifier(self):
            return self._identifier

        @property
        def signature(self):
            return self._signature

        @property
        def footprint(self):
            return "SignatureResponsePayload:" + self._identifier.encode("HEX")

    def generate_footprint(self, identifier):
        assert isinstance(identifier, str)
        assert len(identifier) == 20
        return "SignatureResponsePayload:" + identifier.encode("HEX")

class IdentityPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, address):
            assert isinstance(address, tuple)
            assert len(address) == 2
            assert isinstance(address[0], str)
            assert isinstance(address[1], int)
            super(IdentityPayload.Implementation, self).__init__(meta)
            self._address = address

        @property
        def address(self):
            return self._address

class IdentityRequestPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, mid):
            assert isinstance(mid, str)
            assert len(mid) == 20
            super(IdentityRequestPayload.Implementation, self).__init__(meta)
            self._mid = mid

        @property
        def mid(self):
            return self._mid

class SyncPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, global_time, bloom_filter):
            if __debug__:
                from Bloomfilter import BloomFilter
            assert isinstance(global_time, (int, long))
            assert isinstance(bloom_filter, BloomFilter)
            super(SyncPayload.Implementation, self).__init__(meta)
            self._global_time = global_time
            self._bloom_filter = bloom_filter

        @property
        def global_time(self):
            return self._global_time

        @property
        def bloom_filter(self):
            return self._bloom_filter

class SimilarityPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, cluster, similarity):
            """
            The payload for a dispersy-similarity message.

            CLUSTER is the cluster that we want the similarity for (note
            that one member can have multiple similarity bitstrings, they
            are identified by message.destination.cluster).

            SIMILARITY is a BloomFilter containing the similarity bits.
            The bloom filter must have the same size as is defined in the
            meta Message.
            """
            if __debug__:
                from Bloomfilter import BloomFilter
            assert isinstance(cluster, int)
            assert 0 < cluster < 2^8, "CLUSTER must fit in one byte"
            assert isinstance(similarity, BloomFilter)
            super(SimilarityPayload.Implementation, self).__init__(meta)
            self._cluster = cluster
            self._similarity = similarity

        @property
        def cluster(self):
            return self._cluster

        @property
        def similarity(self):
            return self._similarity

class SimilarityRequestPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, cluster, members):
            """
            The payload for a dispersy-similarity-request message.

            CLUSTER is the cluster that we want the similarity for (note
            that one member can have multiple similarity bitstrings, they
            are identified by message.destination.cluster).

            MEMBERS is a list with Member instances for wich we want the
            similarity.  We specifically need a list of members here,
            because we are unable to uniquely identify a single Member
            using the 20 byte sha1 hash.
            """
            if __debug__:
                from Member import Member
            assert isinstance(cluster, int)
            assert 0 < cluster < 2^8, "CLUSTER must fit in one byte"
            assert isinstance(members, (tuple, list))
            assert not filter(lambda x: not isinstance(x, Member), members)
            super(SimilarityRequestPayload.Implementation, self).__init__(meta)
            self._cluster = cluster
            self._members = members

        @property
        def cluster(self):
            return self._cluster

        @property
        def members(self):
            return self._members

