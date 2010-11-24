class Payload(object):
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

    def __str__(self):
        return "<{0.__class__.__name__} {0.type}>".format(self)

class Authorize(Payload):
    def __init__(self, to, payload):
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
        self._to = to
        self._payload = payload

    @property
    def type(self):
        return u"authorize"

    @property
    def to(self):
        return self._to

    @property
    def payload(self):
        return self._payload

class Revoke(Payload):
    def __init__(self, to, payload):
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
        self._to = to
        self._payload = payload

    @property
    def type(self):
        return u"revoke"

    @property
    def to(self):
        return self._to

    @property
    def payload(self):
        return self._payload

class Permit(Payload):
    @property
    def type(self):
        return u"permit"

class MissingSequencePayload(Permit):
    def __init__(self, member, message, missing_low, missing_high):
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

class ResponsePayload(Permit):
    def __init__(self, request_id):
        assert isinstance(request_id, str)
        assert len(request_id) == 20
        self._request_id = request_id

    @property
    def request_id(self):
        return self._request_id

class CallbackRequestPayload(Permit):
    def __init__(self, source_address, destination_address):
        assert isinstance(source_address, tuple)
        assert len(source_address) == 2
        assert isinstance(source_address[0], str)
        assert isinstance(source_address[1], int)
        assert isinstance(destination_address, tuple)
        assert len(destination_address) == 2
        assert isinstance(destination_address[0], str)
        assert isinstance(destination_address[1], int)
        self._source_address = source_address
        self._destination_address = destination_address

    @property
    def source_address(self):
        return self._source_address

    @property
    def destination_address(self):
        return self._destination_address

class CallbackResponsePayload(ResponsePayload):
    def __init__(self, source_address, destination_address):
        assert isinstance(source_address, tuple)
        assert len(source_address) == 2
        assert isinstance(source_address[0], str)
        assert isinstance(source_address[1], int)
        assert isinstance(destination_address, tuple)
        assert len(destination_address) == 2
        assert isinstance(destination_address[0], str)
        assert isinstance(destination_address[1], int)
        self._source_address = source_address
        self._destination_address = destination_address

    @property
    def source_address(self):
        return self._source_address

    @property
    def destination_address(self):
        return self._destination_address

class SignatureResponsePayload(ResponsePayload):
    def __init__(self, request_id, signature):
        super(SignatureResponsePayload, self).__init__(request_id)
        self._signature = signature

    @property
    def signature(self):
        return self._signature

class IdentityPayload(Permit):
    def __init__(self, address):
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        self._address = address

    @property
    def address(self):
        return self._address

class IdentityRequestPayload(Permit):
    def __init__(self, mid):
        assert isinstance(mid, str)
        assert len(mid) == 20
        self._mid = mid

    @property
    def mid(self):
        return self._mid

class SyncPayload(Permit):
    def __init__(self, global_time, bloom_filter):
        if __debug__:
            from Bloomfilter import BloomFilter
        assert isinstance(global_time, (int, long))
        assert isinstance(bloom_filter, BloomFilter)
        self._global_time = global_time
        self._bloom_filter = bloom_filter

    @property
    def global_time(self):
        return self._global_time

    @property
    def bloom_filter(self):
        return self._bloom_filter

class SimilarityPayload(Permit):
    def __init__(self, cluster, similarity):
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
        self._cluster = cluster
        self._similarity = similarity

    @property
    def cluster(self):
        return self._cluster

    @property
    def similarity(self):
        return self._similarity

class SimilarityRequestPayload(Permit):
    def __init__(self, cluster, members):
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
        self._cluster = cluster
        self._members = members

    @property
    def cluster(self):
        return self._cluster

    @property
    def members(self):
        return self._members

