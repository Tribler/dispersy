from ..community import Community, HardKilledCommunity
from ..conversion import BinaryConversion
from ..exception import ConversionNotFoundException


class TrackerHardKilledCommunity(HardKilledCommunity):

    def __init__(self, *args, **kargs):
        super(TrackerHardKilledCommunity, self).__init__(*args, **kargs)
        # communities are cleaned based on a 'strike' rule.  periodically, we will check is there
        # are active candidates, when there are 'strike' is set to zero, otherwise it is incremented
        # by one.  once 'strike' reaches a predefined value the community is cleaned
        self._strikes = 0

    def update_strikes(self, now):
        # does the community have any active candidates
        self._strikes += 1
        return self._strikes

    def dispersy_on_introduction_request(self, messages):
        hex_cid = messages[0].community.cid.encode("HEX")
        for message in messages:
            host, port = message.candidate.sock_addr
            print "DESTROY_OUT", hex_cid,
            message.authentication.member.mid.encode("HEX"),
            ord(message.conversion.dispersy_version),
            ord(message.conversion.community_version), host, port

        return super(TrackerHardKilledCommunity, self).dispersy_on_introduction_request(messages)


class TrackerCommunity(Community):

    """
    This community will only use dispersy-candidate-request and dispersy-candidate-response messages.
    """

    def __init__(self, *args, **kargs):
        super(TrackerCommunity, self).__init__(*args, **kargs)
        # communities are cleaned based on a 'strike' rule.  periodically, we will check is there
        # are active candidates, when there are 'strike' is set to zero, otherwise it is incremented
        # by one.  once 'strike' reaches a predefined value the community is cleaned
        self._strikes = 0

        self._walked_stumbled_candidates = self._iter_categories([u'walk', u'stumble'])

    def initiate_meta_messages(self):
        messages = super(TrackerCommunity, self).initiate_meta_messages()

        # remove all messages that we should not be using
        tracker_messages = [u"dispersy-introduction-request",
                            u"dispersy-introduction-response",
                            u"dispersy-puncture-request",
                            u"dispersy-puncture",
                            u"dispersy-identity",
                            u"dispersy-missing-identity",

                            u"dispersy-authorize",
                            u"dispersy-revoke",
                            u"dispersy-missing-proof",
                            u"dispersy-destroy-community"]

        messages = [message for message in messages if message.name in tracker_messages]
        return messages

    @property
    def dispersy_auto_download_master_member(self):
        return False

    @property
    def dispersy_enable_candidate_walker(self):
        return False

    @property
    def dispersy_enable_candidate_walker_responses(self):
        return True

    @property
    def dispersy_acceptable_global_time_range(self):
        # we will accept the full 64 bit global time range
        return 2 ** 64 - self._global_time

    def update_strikes(self, now):
        # does the community have any active candidates
        if any(self.dispersy_yield_verified_candidates()):
            self._strikes = 0
        else:
            self._strikes += 1
        return self._strikes

    def initiate_conversions(self):
        return [BinaryConversion(self, "\x00")]

    def get_conversion_for_packet(self, packet):
        try:
            return super(TrackerCommunity, self).get_conversion_for_packet(packet)

        except ConversionNotFoundException:
            # did we create a conversion for this community_version?
            for conversion in self._conversions:
                if conversion.community_version == packet[1]:
                    break

            # no matching conversion, create one and try again
            else:
                if packet[0] == "\x00":
                    self.add_conversion(BinaryConversion(self, packet[1]))
                    return super(TrackerCommunity, self).get_conversion_for_packet(packet)

            # cannot decode this message, probably not a intro-request, etc.
            raise

    def take_step(self):
        raise RuntimeError("a tracker should not walk")

    def dispersy_cleanup_community(self, message):
        # since the trackers use in-memory databases, we need to store the destroy-community
        # message, and all associated proof, separately.
        host, port = message.candidate.sock_addr
        print "DESTROY_IN", self._cid.encode("HEX"), message.authentication.member.mid.encode("HEX"),
        ord(message.conversion.dispersy_version), ord(message.conversion.community_version), host, port

        write = open(self._dispersy.persistent_storage_filename, "a+").write
        write("# received dispersy-destroy-community from %s\n" % (str(message.candidate),))

        identity_id = self._meta_messages[u"dispersy-identity"].database_id
        execute = self._dispersy.database.execute
        messages = [message]
        stored = set()
        while messages:
            message = messages.pop()

            if not message.packet in stored:
                stored.add(message.packet)
                write(" ".join((message.name, message.packet.encode("HEX"), "\n")))

                if not message.authentication.member.public_key in stored:
                    try:
                        packet, = execute(u"SELECT packet FROM sync WHERE meta_message = ? AND member = ?", (
                            identity_id, message.authentication.member.database_id)).next()
                    except StopIteration:
                        pass
                    else:
                        write(" ".join(("dispersy-identity", str(packet).encode("HEX"), "\n")))

                _, proofs = self._timeline.check(message)
                messages.extend(proofs)

        return TrackerHardKilledCommunity

    def on_introduction_request(self, messages):
        if not self._dispersy._silent:
            hex_cid = self.cid.encode("HEX")
            for message in messages:
                host, port = message.candidate.sock_addr
                print "REQ_IN2", hex_cid,
                message.authentication.member.mid.encode("HEX"),
                ord(message.conversion.dispersy_version),
                ord(message.conversion.community_version), host, port

        return super(TrackerCommunity, self).on_introduction_request(messages)

    def on_introduction_response(self, messages):
        if not self._dispersy._silent:
            hex_cid = self.cid.encode("HEX")
            for message in messages:
                host, port = message.candidate.sock_addr
                print "RES_IN2", hex_cid,
                message.authentication.member.mid.encode("HEX"),
                ord(message.conversion.dispersy_version),
                ord(message.conversion.community_version), host, port

        return super(TrackerCommunity, self).on_introduction_response(messages)
