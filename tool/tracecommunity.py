from ..dispersy import Dispersy
from ..callback import Callback

import sys
import os
from time import time
import cProfile

from ...community.channel.payload import TorrentPayload, CommentPayload,\
    MarkTorrentPayload, ModerationPayload, ModificationPayload
from ...community.channel.community import ChannelCommunity
from collections import Counter

def main():
    if len(sys.argv) < 3:
        print >> sys.stderr, "Must specify the path of the dispersy database and the cid"
        sys.exit(1)

    profile = False
    if len(sys.argv) == 4:
        profile = bool(sys.argv[3])

    db_file = sys.argv[1]
    cid = sys.argv[2]
    cid = cid.decode("hex")
    assert len(cid) == 20, len(cid)

    full_db_file = os.path.abspath(db_file)
    state_dir, db_filename = os.path.split(full_db_file)
    db_filename = "../"+db_filename

    print >> sys.stderr, "Using %s as statedir, and %s as db_filename"%(state_dir, db_filename)

    dispersy = Dispersy(Callback(), unicode(state_dir), unicode(db_filename))
    dispersy.database.commit = lambda: True
    dispersy.define_auto_load(ChannelCommunity, kargs = {'integrate_with_tribler':False})

    community = dispersy.get_community(cid, True)
    packets = [str(packet) for packet, in dispersy.database.execute(u'SELECT packet FROM sync WHERE community = %d'%community._database_id)]

    if profile:
        cProfile.runctx('do_trace(dispersy, community, packets)', globals(), {'dispersy':dispersy, 'community':community, 'packets':packets})
    else:
        do_trace(dispersy, community, packets)

def do_trace(dispersy, community, packets):
    message_trace = {}
    message_types = set()
    members = set()

    print >> sys.stderr, "Found %d packets, attempting to convert them..."%len(packets)
    for i, packet in enumerate(packets):
        if i > 0 and i % 10000 == 0:
            print >> sys.stderr, i,

        message = dispersy.convert_packet_to_message(packet, community, load=False, auto_load=False, verify = False)
        payload = message.payload
        mid = message.authentication.member.mid

        if hasattr(payload, 'timestamp'):
            timestamp = payload.timestamp
            timestamp = int((timestamp / 60.0)) * 60

            message_trace.setdefault(timestamp, set()).add(payload)
            message_types.add(str(type(payload._meta)))
            members.add(mid)

    print >> sys.stderr, "\nConverted all packets, creating trace now"

    keys = message_trace.keys()
    keys.sort()

    print "#packets were created by %d users"%len(members)
    print "#time messagetype diff+ messagetype cumul+"
    print "#", " ".join(message_types), " ".join(message_types)

    total_messagetypes = Counter()
    for key in keys:
        sum_messagetypes = Counter()
        for payload in message_trace[key]:
            message_type = str(type(payload._meta))
            sum_messagetypes[message_type] += 1
            total_messagetypes[message_type] += 1

        print key,
        for message_type in message_types:
            print sum_messagetypes[message_type],

        for message_type in message_types:
            print total_messagetypes[message_type],

        print ""
