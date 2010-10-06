import thread
import hashlib
import apsw

from Singleton import Singleton
from Tribler.Core.Dispersy.Print import dprint

class DatabaseException(Exception):
    pass

# class DatabaseRollbackException(DatabaseException):
#     pass

class Database(Singleton):
    def __init__(self, file_path):
        if __debug__:
            self._thread_ident = thread.get_ident()
        assert isinstance(file_path, unicode)

        self._connection = apsw.Connection(file_path)
        # self._connection.setrollbackhook(self._on_rollback)
        self._cursor = self._connection.cursor()

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
                dprint(exception=True)
                dprint("Filename: ", self._connection.filename)
                dprint("Changes (UPDATE, INSERT, DELETE): ", self._connection.totalchanges() - changes_before)
                dprint(statements)
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
    
