"""
This module provides an interface to the Dispersy database.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from itertools import groupby

from .database import Database
from .distribution import FullSyncDistribution


LATEST_VERSION = 21

schema = u"""
CREATE TABLE member(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mid BLOB,                                      -- member identifier (sha1 of public_key)
 public_key BLOB,                               -- member public key
 private_key BLOB);                             -- member private key
CREATE INDEX member_mid_index ON member(mid);

CREATE TABLE community(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 master INTEGER REFERENCES member(id),          -- master member (permission tree root)
 member INTEGER REFERENCES member(id),          -- my member (used to sign messages)
 classification TEXT,                           -- community type, typically the class name
 auto_load BOOL DEFAULT 1,                      -- when 1 this community is loaded whenever a packet for it is received
 database_version INTEGER DEFAULT """ + str(LATEST_VERSION) + """,
 UNIQUE(master));

CREATE TABLE meta_message(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 name TEXT,
 priority INTEGER DEFAULT 128,
 direction INTEGER DEFAULT 1,                           -- direction used when synching (1 for ASC, -1 for DESC)
 UNIQUE(community, name));

--CREATE TABLE reference_member_sync(
-- member INTEGER REFERENCES member(id),
-- sync INTEGER REFERENCES sync(id),
-- UNIQUE(member, sync));

CREATE TABLE double_signed_sync(
 sync INTEGER REFERENCES sync(id),
 member1 INTEGER REFERENCES member(id),
 member2 INTEGER REFERENCES member(id));
CREATE INDEX double_signed_sync_index_0 ON double_signed_sync(member1, member2);

CREATE TABLE sync(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 member INTEGER REFERENCES member(id),                  -- the creator of the message
 global_time INTEGER,
 meta_message INTEGER REFERENCES meta_message(id),
 undone INTEGER DEFAULT 0,
 packet BLOB,
 sequence INTEGER,
 UNIQUE(community, member, global_time));
CREATE INDEX sync_meta_message_undone_global_time_index ON sync(meta_message, undone, global_time);
CREATE INDEX sync_meta_message_member ON sync(meta_message, member);

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '""" + str(LATEST_VERSION) + """');
"""

class DatabaseVersionTooLowError(Exception):
    pass

class DatabaseVersionTooHighError(Exception):
    pass

class DispersyDatabase(Database):
    if __debug__:
        __doc__ = schema

    def check_database(self, database_version):
        assert isinstance(database_version, unicode)
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version = int(database_version)

        if database_version == 0:
            # setup new database with current database_version
            self.executescript(schema)
            self.commit()

        else:
            # Check if the version is not higher than our current known version number.
            if database_version > LATEST_VERSION:
                raise DatabaseVersionTooHighError(u"The database was created with a more recent dispersy version.")

            # Check if the version is below what we support.
            if database_version < 16:
                raise DatabaseVersionTooLowError(u"Database version too low to upgrade.")

            # upgrade from version 16 to version 17
            if database_version < 17:
                # 23/09/13 Boudewijn: by rewriting the Member constructor to find the member using
                # the mid instead of the public_key, we no longer need to have an index on the
                # public_key column.  this greatly reduces the bytes written when creating new
                # Member instances.  unfortunately this requires the removal of the UNIQUE clause,
                # however, the python code already guarantees that the public_key remains unique.
                self._logger.info("upgrade database %d -> %d", database_version, 17)
                self.executescript(u"""
-- move / remove old member table
DROP INDEX IF EXISTS member_mid_index;
ALTER TABLE member RENAME TO old_member;
-- create new member table
CREATE TABLE member(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mid BLOB,                                      -- member identifier (sha1 of public_key)
 public_key BLOB,                               -- member public key
 tags TEXT DEFAULT '');                         -- comma separated tags: store, ignore, and blacklist
CREATE INDEX member_mid_index ON member(mid);
-- fill new member table with old data
INSERT INTO member (id, mid, public_key, tags) SELECT id, mid, public_key, tags FROM old_member;
-- remove old member table
DROP TABLE old_member;
-- update database version
UPDATE option SET value = '17' WHERE key = 'database_version';
""")
                self.commit()
                self._logger.info("upgrade database %d -> %d (done)", database_version, 17)

            # upgrade from version 17 to version 18
            if database_version < 18:
                # In version 18, we remove the tags column as we don't have blackisting anymore
                self._logger.debug("upgrade database %d -> %d", database_version, 18)
                self.executescript(u"""
-- move / remove old member table
DROP INDEX IF EXISTS member_mid_index;
ALTER TABLE member RENAME TO old_member;
-- create new member table
CREATE TABLE member(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mid BLOB,                                      -- member identifier (sha1 of public_key)
 public_key BLOB);                               -- member public key
CREATE INDEX member_mid_index ON member(mid);
-- fill new member table with old data
INSERT INTO member (id, mid, public_key) SELECT id, mid, public_key FROM old_member;
-- remove old member table
DROP TABLE old_member;
-- remove table malicious_proof
DROP TABLE IF EXISTS malicious_proof;
-- update database version
UPDATE option SET value = '18' WHERE key = 'database_version';
""")
                self.commit()
                self._logger.debug("upgrade database %d -> %d (done)", database_version, 18)

            # upgrade from version 18 to version 19
            if database_version < 19:
                # In version 19, we move the private key to member, as it doesn't improve anything and it allows us to
                # actually simplify the code.
                self._logger.debug("upgrade database %d -> %d", database_version, 19)

                self.executescript(u"""
-- move / remove old member table
DROP INDEX IF EXISTS member_mid_index;
ALTER TABLE member RENAME TO old_member;
-- create new member table
 CREATE TABLE member(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 mid BLOB,                                      -- member identifier (sha1 of public_key)
 public_key BLOB,                               -- member public key
 private_key BLOB);                             -- member private key
CREATE INDEX member_mid_index ON member(mid);
-- fill new member table with old data
INSERT INTO member (id, mid, public_key, private_key)
                SELECT id, mid, public_key, private_key.private_key FROM old_member
                LEFT JOIN private_key ON private_key.member = old_member.id;
-- remove old member table
DROP TABLE old_member;
-- remove table private_key
DROP TABLE IF EXISTS private_key;
-- update database version
UPDATE option SET value = '19' WHERE key = 'database_version';
""")
                self.commit()
                self._logger.debug("upgrade database %d -> %d (done)", database_version, 19)

            # Upgrade from 19 to 20
            if database_version < 20:
                # Let's store the sequence numbers in the database instead of quessing
                self._logger.debug("upgrade database %d -> %d", database_version, 20)

                self.executescript(u"""
DROP INDEX IF EXISTS sync_meta_message_undone_global_time_index;
DROP INDEX IF EXISTS sync_meta_message_member;
""")
                old_sync = list(self.execute(u"""
                    SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'old_sync';"""))
                if old_sync:
                    # delete the sync table and start copying data again
                    self.executescript(u"""
DROP TABLE IF EXISTS sync;
DROP INDEX IF EXISTS sync_meta_message_undone_global_time_index;
DROP INDEX IF EXISTS sync_meta_message_member;
""")
                else:
                    # rename sync to old_sync if it is the first time
                    self.executescript(u"ALTER TABLE sync RENAME TO old_sync;")

                self.executescript(u"""
CREATE TABLE IF NOT EXISTS sync(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    community INTEGER REFERENCES community(id),
    member INTEGER REFERENCES member(id),                  -- the creator of the message
    global_time INTEGER,
    meta_message INTEGER REFERENCES meta_message(id),
    undone INTEGER DEFAULT 0,
    packet BLOB,
    sequence INTEGER,
    UNIQUE(community, member, global_time, sequence));

CREATE INDEX sync_meta_message_undone_global_time_index ON sync(meta_message, undone, global_time);
CREATE INDEX sync_meta_message_member ON sync(meta_message, member);

INSERT INTO sync  (id, community, member, global_time, meta_message, undone, packet, sequence)
    SELECT id, community, member, global_time, meta_message, undone, packet, NULL FROM old_sync;

DROP TABLE IF EXISTS old_sync;

UPDATE option SET value = '20' WHERE key = 'database_version';
""")
                self.commit()
                self._logger.debug("upgrade database %d -> %d (done)", database_version, 20)

            # Upgrade from 20 to 21
            if database_version < 21:
                # remove 'cluster' column from meta_message table
                self._logger.debug("upgrade database %d -> %d", database_version, 21)
                self.executescript(u"""
CREATE TABLE meta_message_new(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 name TEXT,
 priority INTEGER DEFAULT 128,
 direction INTEGER DEFAULT 1,                           -- direction used when synching (1 for ASC, -1 for DESC)
 UNIQUE(community, name));

INSERT INTO meta_message_new(id, community, name, priority, direction)
  SELECT id, community, name, priority, direction FROM meta_message ORDER BY id;

DROP TABLE meta_message;
ALTER TABLE meta_message_new RENAME TO meta_message;

UPDATE option SET value = '21' WHERE key = 'database_version';""")
                self.commit()
                self._logger.debug("upgrade database %d -> %d (done)", database_version, 21)

            new_db_version = 22
            if database_version < new_db_version:
                # there is no version new_db_version yet...
                # self._logger.debug("upgrade database %d -> %d", database_version, new_db_version)
                # self.executescript(u"""UPDATE option SET value = '22' WHERE key = 'database_version';""")
                # self.commit()
                # self._logger.debug("upgrade database %d -> %d (done)", database_version, new_db_version)
                pass

        return LATEST_VERSION

    def check_community_database(self, community, database_version):
        assert isinstance(database_version, int)
        assert database_version >= 0

        if database_version < 21:
            self._logger.debug("upgrade community %d -> %d", database_version, 20)

            # patch 14 -> 15 notes:
            #
            # because of a bug in handling messages with sequence numbers, it was possible for
            # messages to be stored in the database with missing sequence numbers.  I.e. numbers 1,
            # 2, and 5 could be stored leaving 3 and 4 missing.
            #
            # this results in the problem that the message with sequence number 5 is believed to be
            # a message with sequence number 3.  resulting in an inconsistent database and an
            # inability to correctly handle missing sequence messages and incoming messages with
            # specific sequence numbers.
            #
            # we will 'solve' this by removing all messages after a 'gap' occurred in the sequence
            # numbers.  In our example it will result in the message with sequence number 5 to be
            # removed.
            #
            # we choose not to call any undo methods because both the timeline and the votes can
            # handle the resulting multiple calls to the undo callback.
            #
            # patch 15 -> 16 notes:
            #
            # because of a bug in handling messages with sequence numbers, it was possible for
            # messages to be stored in the database with conflicting global time values.  For
            # example, M@6#1 and M@5#2 could be in the database.
            #
            # This could occur when a peer removed the Dispersy database but not the public/private
            # key files, resulting in a fresh sequence number starting at 1.  Different peers would
            # store different message combinations.  Incoming message checking incorrectly allowed
            # this to happen, resulting in many peers consistently dropping messages.
            #
            # New rules will ensure all peers converge to the same database content.  However, we do
            # need to remove the messages that have previously been (incorrectly) accepted.
            #
            # The rules are as follows:
            # - seq(M_i), where i = 1 is the first message in the sequence
            # - seq(M_j) = seq(M_i) - 1, where i = j - 1
            # - gt(M_i) < gt(M_j), where i = j - 1

            # all meta messages that use sequence numbers
            metas = [meta for meta in community.get_meta_messages() if (
                isinstance(meta.distribution, FullSyncDistribution) and meta.distribution.enable_sequence_number)]
            convert_packet_to_message = community.dispersy.convert_packet_to_message

            progress = 0
            count = 0
            deletes = []
            for meta in metas:
                i, = next(self.execute(u"SELECT COUNT(*) FROM sync WHERE meta_message = ?", (meta.database_id,)))
                count += i
            self._logger.debug("checking %d sequence number enabled messages [%s]", count, community.cid.encode("HEX"))
            if count > 50:
                progress_handlers = [handler("Upgrading database", "Please wait while we upgrade the database", count)
                                     for handler in community.dispersy.get_progress_handlers()]
            else:
                progress_handlers = []

            sequence_updates = []
            for meta in metas:
                rows = list(self.execute(u"SELECT id, member, packet FROM sync "
                                         u"WHERE meta_message = ? ORDER BY member, global_time", (meta.database_id,)))
                groups = groupby(rows, key=lambda tup: tup[1])
                for member_id, iterator in groups:
                    last_global_time = 0
                    last_sequence_number = 0
                    for packet_id, _, packet in iterator:
                        message = convert_packet_to_message(str(packet), community, verify=False)
                        if message:
                            assert message.authentication.member.database_id == member_id
                            if (last_sequence_number + 1 == message.distribution.sequence_number and
                                        last_global_time < message.distribution.global_time):
                                # message is OK
                                sequence_updates.append((message.distribution.sequence_number, packet_id))
                                last_sequence_number += 1
                                last_global_time = message.distribution.global_time

                            else:
                                deletes.append((packet_id,))
                                self._logger.debug("delete id:%d", packet_id)
                        else:
                            deletes.append((packet_id,))
                            self._logger.debug("delete id:%d", packet_id)

                        progress += 1
                        if progress % 25 == 0:
                            for handler in progress_handlers:
                                handler.Update(progress)

            for handler in progress_handlers:
                handler.Update(progress, "Saving the results...")

            self._logger.debug("will delete %d packets from the database", len(deletes))
            if deletes:
                self.executemany(u"DELETE FROM sync WHERE id = ?", deletes)

            if sequence_updates:
                self.executemany(u"UPDATE sync SET sequence = ? WHERE id = ?", sequence_updates)

            # we may have removed some undo-other or undo-own messages.  we must ensure that there
            # are no messages in the database that point to these removed messages
            updates = list(self.execute(u"""
            SELECT a.id
            FROM sync a
            LEFT JOIN sync b ON a.undone = b.id
            WHERE a.community = ? AND a.undone > 0 AND b.id IS NULL""", (community.database_id,)))
            if updates:
                self.executemany(u"UPDATE sync SET undone = 0 WHERE id = ?", updates)

            self.execute(u"UPDATE community SET database_version = 21 WHERE id = ?", (community.database_id,))
            self.commit()

            for handler in progress_handlers:
                handler.Destroy()

        return LATEST_VERSION
