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

--CREATE TABLE member(
-- community INTEGER REFERENCES community(id),
-- user INTEGER REFERENCES user(id));
 
CREATE TABLE full_sync(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 sequence INTEGER,
 packet BLOB);

CREATE TABLE minimal_sync(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user INTEGER REFERENCES user(id),
 community INTEGER REFERENCES community(id),
 global INTEGER,
 sequence INTEGER,
 minimal INTEGER,
 packet BLOB);

CREATE TABLE option(key STRING PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '1');
""")

        elif database_version == "1":
            # current version requires no action
            pass
                         
        else:
            # unknown database version
            raise ValueError

    def _dump_community(self):
        def helper():
            yield "%4s %43s %12s" % ("id", "CID", "PEM-size")
            for id, cid, pem in self.execute(u"SELECT * FROM community ORDER BY id"):
                yield "%4d %43s %7d bytes" % (id, str(cid).encode("HEX"), len(pem))
        return "-- table: community --\n" + "\n".join(helper())

    def _dump_user(self):
        def helper():
            yield "%4s %43s %12s" % ("id", "MID", "PEM-size")
            for id, mid, pem in self.execute(u"SELECT * FROM user ORDER BY id"):
                yield "%4d %43s %7d bytes" %(id, str(mid).encode("HEX"), len(pem))
        return "-- table: user --\n" + "\n".join(helper())

    # def _dump_member(self):
    #     def helper():
    #         yield "%4s %4s" % ("cmty", "user")
    #         for community, user in self.execute(u"SELECT * FROM member ORDER BY community, user"):
    #             yield "%4d %4d" % (community, user)
    #     return "-- table: member --\n" + "\n".join(helper())

    def _dump_full_sync(self):
        def helper():
            yield "%4s %4s %4s %4s %4s %12s" % ("id", "user", "cmty", "glob", "seq", "packet-size")
            for id, user, community, global_time, sequence_number, packet in self.execute(u"SELECT * FROM full_sync ORDER BY id"):
                yield "%4d %4d %4d %4d %4d %7d bytes" % (id, user, community, global_time, sequence_number, len(packet))
        return "-- table: full_sync --\n" + "\n".join(helper())

    def _dump_minimal_sync(self):
        def helper():
            yield "%4s %4s %4s %4s %4s %4s %12s" % ("id", "user", "cmty", "glob", "seq", "mima", "packet-size")
            for id, user, community, global_time, sequence_number, minimal_count, packet in self.execute(u"SELECT * FROM minimal_sync ORDER BY id"):
                yield "%4d %4d %4d %4d %4d %4d %7d bytes" % (id, user, community, global_time, sequence_number, minimal_count, len(packet))
        return "-- table: minimal_sync --\n" + "\n".join(helper())

    def _dump_option(self):
        def helper():
            yield "%35s %12s   %s" % ("key", "value-size", "value")
            for key, value in self.execute(u"SELECT * FROM option ORDER BY key"):
                size = len(value)
                if str(value).isalnum():
                    value = "\"%s\"" % value
                else:
                    value = "---"
                yield "%35s %7d bytes  %s" % (key, size, value)
        return "-- table: option --\n" + "\n".join(helper())

    def __str__(self):
        return "\n\n".join((self._dump_community(), self._dump_user(), self._dump_full_sync(), self._dump_minimal_sync(), self._dump_option()))

