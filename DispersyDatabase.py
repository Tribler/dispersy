from hashlib import sha1
from os import path

from Database import Database

class DispersyDatabase(Database):

    def __init__(self, working_directory):
        assert isinstance(working_directory, unicode)
        return Database.__init__(self, path.join(working_directory, u"dispersy.db"))

    def check_database(self, database_version):
        if database_version == "0":
            self.execute(u"""
CREATE TABLE user(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 mid BLOB,                                      -- member identifier (sha1 of pem)
 pem BLOB);                                     -- member key (public part)

CREATE TABLE community(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 user INTEGER REFERENCES user(id),              -- my member that is used to sign my messages
 cid BLOB,                                      -- community identifier (sha1 of pem)
 master_pem BLOB);                              -- community master key (public part)

CREATE TABLE key(
 public_pem BLOB,                               -- public part
 private_pem BLOB);                             -- private part

CREATE TABLE routing(
 user INTEGER REFERENCES user(id),
 host TEXT,                                     -- IP address
 port INTEGER,                                  -- port number
 time TEXT,                                     -- time when received data
 UNIQUE(user, host, port));
 
CREATE TABLE sync_full(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 sequence INTEGER,
 packet BLOB);

CREATE TABLE sync_minimal(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 minimal INTEGER,
 packet BLOB);

CREATE TABLE sync_last(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 packet BLOB);

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '1');
""")

            # Add bootstrap users
            self.bootstrap()

        elif database_version == "1":
            # current version requires no action
            pass

    def bootstrap(self):
        host = u"mughal.tribler.org"
        port = 6711
        mid = "1204a6c35d236d13ac326570cbd62cdac432f865".decode("HEX")
        pem = """-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDTMh5IsI7MALcr70QnpHLSh/jw
yjPRKuXScweuhE92gzSvNJ1pafQKpaKr6W8atWnHSja+TMksm1EdOU5+F392/xD1
sgE4Q3oy8w/ZWEEVlywFXlR+Uepl6q9fFO7QjUoxkPLBQKFxguAc8Hr9p6czt5h/
zPr/msrf64x2YKuoPwIBBQ==
-----END PUBLIC KEY-----
"""
        self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
        self.execute(u"INSERT INTO routing(user, host, port, time) VALUES(?, ?, ?, '0000-0-0 0:0:0')",
                     (self.get_last_insert_rowid(), host, port))

        host = u"mughal.tribler.org"
        port = 6712
        mid = "1204a6c35d236d13ac326570cbd62cdac432f865".decode("HEX")
        pem = """-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDAu3+CFRrYYoBge+lKn1Ty5wbu
89wzfAHo+rt6/OEhelWnMTMGZn0Xb6jGS0oU0grhtvurWXQyZ6uPuZO4q/su8aeT
F2RBGJ+zXHm9tlpiIxxUQTFKiilwsQtIFCpw+v0shnPt/LtoG1Y3mTSXyzXp2FLZ
Q6DMokT4fOGpdap57wIBBQ==
-----END PUBLIC KEY-----
"""
        self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
        self.execute(u"INSERT INTO routing(user, host, port, time) VALUES(?, ?, ?, '0000-0-0 0:0:0')",
                     (self.get_last_insert_rowid(), host, port))

        host = u"frayja.com"
        port = 6712
        mid = "ca7a5eebaffe0d08c1afe5253c001569bdea4803".decode("HEX")
        pem = """-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDgOk7d0F6sinM+6XY2pE3SiSNv
AipUkNY4iU0/sEbt+hUnx5oiLAlwq+YAbO095XCWyBAu8zppfS/6n6Bk3rKm6B1C
x14Y8HXJTXyEofgBcsSl9gNBYyaYhJsCalQJpP2WkkQFQsSkhRx9H2S955915/Dz
ddbv3NkHuZ+G0HrjRQIBBQ==
-----END PUBLIC KEY-----
"""
        self.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(mid), buffer(pem)))
        self.execute(u"INSERT INTO routing(user, host, port, time) VALUES(?, ?, ?, '0000-0-0 0:0:0')",
                     (self.get_last_insert_rowid(), host, port))
