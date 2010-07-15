from Database import Database

class DispersyDatabase(Database):
    def check_database(self, database_version):
        if database_version == "0":
            self.execute(u"""
CREATE TABLE community(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 cid BLOB,                                      -- global community identifier
 pem BLOB);                                     -- global community master key

CREATE TABLE user(
 id INTEGER PRIMARY KEY AUTOINCREMENT,          -- local counter for database optimization
 mid BLOB,
 pem BLOB);                                     -- global member key

CREATE TABLE routing(
 user INTEGER REFERENCES user(id),
 host TEXT,                                     -- IP address
 port INTEGER,                                  -- port number
 time TEXT,                                     -- time when received data
 UNIQUE(user, host, port));
 
CREATE TABLE sync(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 sequence INTEGER,
 packet BLOB);

CREATE TABLE sync_minimal(
 id INTEGER REFERENCES sync(id),
 minimal INTEGER);

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '1');
""")

        elif database_version == "1":
            # current version requires no action
            pass
                         
        else:
            # unknown database version
            raise ValueError

    def screen_dump(self):
        return Database.screen_dump(self, [u"community", u"user", u"routing", u"sync", u"sync_minimal", u"option"])
