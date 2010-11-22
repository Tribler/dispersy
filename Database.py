import thread
import hashlib
import apsw

from Singleton import Singleton

if __debug__:
    from Tribler.Core.Dispersy.Print import dprint

class DatabaseException(Exception):
    pass

# class DatabaseRollbackException(DatabaseException):
#     pass

class Database(Singleton):
    def __init__(self, file_path):
        if __debug__:
            assert isinstance(file_path, unicode)
            dprint(file_path)
            self._thread_ident = thread.get_ident()

        self._connection = apsw.Connection(file_path)
        # self._connection.setrollbackhook(self._on_rollback)
        self._cursor = self._connection.cursor()

        # database configuration (pragma)
        if __debug__:
            cache_size, = self._cursor.execute(u"PRAGMA cache_size").next()
            page_size, = self._cursor.execute(u"PRAGMA page_size").next()
            page_count, = self._cursor.execute(u"PRAGMA page_count").next()
            dprint("page_size: ", page_size, " (for currently ", page_count * page_size, " bytes in database)")
            dprint("cache_size: ", cache_size, " (for maximal ", cache_size * page_size, " bytes in memory)")

        synchronous, = self._cursor.execute(u"PRAGMA synchronous").next()
        if __debug__: dprint("synchronous: ", synchronous, " (", {0:"OFF", 1:"NORMAL", 2:"FULL"}[synchronous])
        if not synchronous == 0:
            if __debug__: dprint("synchronous: ", synchronous, " (", {0:"OFF", 1:"NORMAL", 2:"FULL"}[synchronous], ") --> 0 (OFF)")
            self._cursor.execute(u"PRAGMA synchronous = 0")

        count_changes, = self._cursor.execute(u"PRAGMA count_changes").next()
        if __debug__: dprint("count_changes: ", count_changes, " (", {0:"False", 1:"True"}[count_changes], ")")
        if not count_changes == 0:
            if __debug__: dprint("count_changes: ", count_changes, " (", {0:"False", 1:"True"}[count_changes], ") --> 0 (False)")
            self._cursor.execute(u"PRAGMA count_changes = 0")

        temp_store, = self._cursor.execute(u"PRAGMA temp_store").next()
        if __debug__: dprint("temp_store: ", temp_store, " (", {0:"DEFAULT", 1:"FILE", 2:"MEMORY"}[temp_store])
        if not temp_store == 3:
            if __debug__: dprint("temp_store: ", temp_store, " (", {0:"DEFAULT", 1:"FILE", 2:"MEMORY"}[temp_store], ") --> 3 (MEMORY)")
            self._cursor.execute(u"PRAGMA temp_store = 3")

        # get version from required 'option' table
        try:
            version = self.execute(u"SELECT value FROM option WHERE key == 'database_version' LIMIT 1").next()[0]
        except DatabaseException:
            # the 'option' table probably hasn't been created yet
            version = u"0"
        except StopIteration:
            # the 'database_version' key was not found
            version = u"0"

        self.check_database(version)

    def __enter__(self):
        self._cursor.execute("BEGIN TRANSACTION")
        return self.execute

    def __exit__(self, exc_type, exc_value, traceback):
        self._cursor.execute("END TRANSACTION")

    @property
    def last_insert_rowid(self):
        assert self._thread_ident == thread.get_ident()
        return self._connection.last_insert_rowid()

    @property
    def changes(self):
        assert self._thread_ident == thread.get_ident()
        return self._connection.changes()

    def execute(self, statements, bindings=()):
        """
        Use a cursor object to execute the sql STATEMENTS.  BINDINGS
        optionally provides replacements for markers in STATEMENTS.

        http://apsw.googlecode.com/svn/publish/cursor.html#cursors
        """
        assert self._thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statements, unicode), "The SQL statement must be given in unicode"
        assert isinstance(bindings, (tuple, list, dict)), "The bindinds must be a tuple, list, or dictionary"
        assert not filter(lambda x: isinstance(x, str), bindings), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB. \nGiven types: %s" % str([type(binding) for binding in bindings]) 
        if __debug__:
            changes_before = self._connection.totalchanges()
            dprint(statements)
        try:
            return self._cursor.execute(statements, bindings)
        except apsw.SQLError, exception:
            if __debug__:
                dprint(exception=True, level="warning")
                dprint("Filename: ", self._connection.filename, level="warning")
                dprint("Changes (UPDATE, INSERT, DELETE): ", self._connection.totalchanges() - changes_before, level="warning")
                dprint(statements, level="warning")
            raise DatabaseException(exception)

    def executemany(self, statements, sequenceofbindings):
        """
        Use a cursor object to execute the sql STATEMENTS.
        SEQUENCEOFBINDINGS provides a list with replacements for
        markers in STATEMENTS.

        Conceptually executemany performs:
        # for bindings in sequenceofbindings:
        #     execute(statements, bindings)

        http://apsw.googlecode.com/svn/publish/cursor.html#cursors
        """
        assert self._thread_ident == thread.get_ident()
        assert isinstance(statements, unicode)
        assert isinstance(sequenceofbindings, (tuple, list))
        assert not filter(lambda x: isinstance(x, (tuple, list, dict)), sequenceofbindings)
        assert not filter(lambda x: not filter(lambda y: isinstance(y, str), bindings), sequenceofbindings), "None of the bindings may be string type"
        if __debug__:
            changes_before = self._connection.totalchanges()
            dprint(statements)
        try:
            return self._cursor.executemany(statements, sequenceofbindings)
        except apsw.SQLError, exception:
            if __debug__:
                dprint(exception=True)
                dprint("Filename: ", self._connection.filename)
                dprint("Changes (UPDATE, INSERT, DELETE): ", self._connection.totalchanges() - changes_before)
                dprint(statements)
            raise DatabaseException(exception)

    # def _on_rollback(self):
    #     if __debug__: dprint("ROLLBACK", level="warning")
    #     raise DatabaseRollbackException(1)

    def check_database(self, database_version):
        """
        This method is called once for each Database instance to
        ensure that the database structure and version is correct.

        DATABASE_VERSION is the 'value' field in the 'option' table
        that is associated to 'key'='database_version'.  The value
        reverts to u'0' when the table could not be accessed.

        The 'option' table must always exist:
        CREATE TABLE option(key STRING, value STRING);
        """
        raise NotImplementedError()
    
