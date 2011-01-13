"""
This module provides an interface to the Dispersy database.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from socket import gethostbyname
from hashlib import sha1
from os import path

from Database import Database

schema = u"""
CREATE TABLE user(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 mid BLOB,                                      -- member identifier (sha1 of pem)
 pem BLOB,                                      -- member key (public part)
 host TEXT,
 port INTEGER,
 UNIQUE(mid));

CREATE TABLE identity(
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 packet BLOB,
 UNIQUE(user, community));

CREATE TABLE community(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 user INTEGER REFERENCES user(id),              -- my member that is used to sign my messages
 cid BLOB,                                      -- community identifier (sha1 of pem)
 master_pem BLOB,                               -- community master key (public part)
 UNIQUE(user, cid));

CREATE TABLE key(
 public_pem BLOB,                               -- public part
 private_pem BLOB,                              -- private part
 UNIQUE(public_pem, private_pem));

CREATE TABLE routing(
 community INTEGER REFERENCES community(id),
 host TEXT,                                     -- IP address
 port INTEGER,                                  -- port number
 incoming_time TEXT,                            -- time when received data
 outgoing_time TEXT,                            -- time when data send
 UNIQUE(community, host, port));

CREATE TABLE name(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 value TEXT);

CREATE TABLE sync(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 user INTEGER REFERENCES user(id),
 name INTEGER REFERENCES name(id),
 global_time INTEGER,
 distribution_sequence INTEGER,                 -- used for the sync-distribution policy
 destination_cluster INTEGER,                   -- used for the similarity-destination policy
 packet BLOB);

CREATE TABLE similarity(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 user INTEGER REFERENCES user(id),
 cluster INTEGER,
 similarity BLOB,
 packet BLOB,
 UNIQUE(community, user, cluster));

-- TODO: remove id, community, user, and cluster columns and replace with refrence to similarity table
-- my_similarity is used to store the similarity bits
-- as set by the user *before* regulating
CREATE TABLE my_similarity (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 community INTEGER REFERENCES community(id),
 user INTEGER REFERENCES user(id),
 cluster INTEGER,
 similarity BLOB,
 UNIQUE(community, user));

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '1');
"""

class DispersyDatabase(Database):
    if __debug__:
        __doc__ = schema

    def __init__(self, working_directory):
        """
        Initialize a new DispersyDatabase instance.

        @type working_directory: unicode
        @param working_directory: the directory name where the database file should be stored.
        """
        assert isinstance(working_directory, unicode)
        return Database.__init__(self, path.join(working_directory, u"dispersy.db"))

    def check_database(self, database_version):
        assert isinstance(database_version, unicode)
        if database_version == u"0":
            self.executescript(schema)

            # Add bootstrap users
            self.bootstrap()

        elif database_version == u"1":
            # current version requires no action
            pass

    def bootstrap(self):
        """
        Populate the database with initial data.

        This method is called after the database is initially created.  It ensures that one or more
        bootstrap nodes are known.  Without these bootstrap nodes no other nodes will ever be found.
        """
#         host = unicode(gethostbyname(u"mughal.tribler.org"))
#         port = 6711
#         mid = "1204a6c35d236d13ac326570cbd62cdac432f865".decode("HEX")
#         pem = """-----BEGIN PUBLIC KEY-----
# MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDTMh5IsI7MALcr70QnpHLSh/jw
# yjPRKuXScweuhE92gzSvNJ1pafQKpaKr6W8atWnHSja+TMksm1EdOU5+F392/xD1
# sgE4Q3oy8w/ZWEEVlywFXlR+Uepl6q9fFO7QjUoxkPLBQKFxguAc8Hr9p6czt5h/
# zPr/msrf64x2YKuoPwIBBQ==
# -----END PUBLIC KEY-----
# """
#         self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
#         self.execute(u"INSERT INTO routing(community, host, port, incoming_time) VALUES(0, ?, ?, '2010-01-01 00:00:00')",
#                      (host, port))

#         host = unicode(gethostbyname(u"frayja.com"))
#         port = 12345
#         mid = "1204a6c35d236d13ac326570cbd62cdac432f865".decode("HEX")
#         pem = """-----BEGIN PUBLIC KEY-----
# MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDAu3+CFRrYYoBge+lKn1Ty5wbu
# 89wzfAHo+rt6/OEhelWnMTMGZn0Xb6jGS0oU0grhtvurWXQyZ6uPuZO4q/su8aeT
# F2RBGJ+zXHm9tlpiIxxUQTFKiilwsQtIFCpw+v0shnPt/LtoG1Y3mTSXyzXp2FLZ
# Q6DMokT4fOGpdap57wIBBQ==
# -----END PUBLIC KEY-----
# """
#         self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
#         self.execute(u"INSERT INTO routing(community, host, port, incoming_time) VALUES(0, ?, ?, '2010-01-01 00:00:00')", (host, port))

        host = unicode(gethostbyname(u"localhost"))
        port = 12345
        mid = "ca7a5eebaffe0d08c1afe5253c001569bdea4803".decode("HEX")
        pem = """-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDgOk7d0F6sinM+6XY2pE3SiSNv
AipUkNY4iU0/sEbt+hUnx5oiLAlwq+YAbO095XCWyBAu8zppfS/6n6Bk3rKm6B1C
x14Y8HXJTXyEofgBcsSl9gNBYyaYhJsCalQJpP2WkkQFQsSkhRx9H2S955915/Dz
ddbv3NkHuZ+G0HrjRQIBBQ==
-----END PUBLIC KEY-----
"""
        self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
        self.execute(u"INSERT INTO routing(community, host, port, incoming_time, outgoing_time) VALUES(0, ?, ?, '2010-01-01 00:00:00', '2010-01-01 00:00:00')", (host, port))
