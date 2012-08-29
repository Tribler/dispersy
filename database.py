"""
This module provides basic database functionalty and simple version control.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

import hashlib
import sqlite3

from revision import update_revision_information
from singleton import Singleton

if __debug__:
    from dprint import dprint
    import thread

# update version information directly from SVN
update_revision_information("$HeadURL$", "$Revision$")

class IgnoreCommits(Exception):
    """
    Ignore all commits made within the body of a 'with database:' clause.

    with database:
       # all commit statements are delayed until the database.__exit__
       database.commit()
       database.commit()
       # raising IgnoreCommits causes all commits to be ignored
       raise IgnoreCommits()
    """
    def __init__(self):
        super(IgnoreCommits, self).__init__("Ignore all commits made within __enter__ and __exit__")

class Database(Singleton):
    def __init__(self, file_path):
        """
        Initialize a new Database instance.

        @param file_path: the path to the database file.
        @type file_path: unicode
        """
        if __debug__:
            assert isinstance(file_path, unicode)
            dprint(file_path)
            self._debug_thread_ident = thread.get_ident()
        self._file_path = file_path

        self._connection = sqlite3.Connection(file_path)
        # self._connection.setrollbackhook(self._on_rollback)
        self._cursor = self._connection.cursor()

        # _commit_callbacks contains a list with functions that are called on each database commit
        self._commit_callbacks = []

        # Database.commit() is enabled when _pending_commits == 0.  Database.commit() is disabled
        # when _pending_commits > 0.  A commit is required when _pending_commits > 1.
        self._pending_commits = 0

        # collect current database configuration
        page_size = int(self._cursor.execute(u"PRAGMA page_size").next()[0])
        journal_mode = str(self._cursor.execute(u"PRAGMA journal_mode").next()[0]).upper()
        synchronous = str(self._cursor.execute(u"PRAGMA synchronous").next()[0]).upper()

        #
        # PRAGMA page_size = bytes;
        # http://www.sqlite.org/pragma.html#pragma_page_size
        # Note that changing page_size has no effect unless performed on a new database or followed
        # directly by VACUUM.  Since we do not want the cost of VACUUM every time we load a
        # database, existing databases must be upgraded.
        #
        if __debug__: dprint("PRAGMA page_size = 8192 (previously: ", page_size, ")")
        if page_size < 8192:
            # it is not possible to change page_size when WAL is enabled
            if journal_mode == u"WAL":
                self._cursor.executescript(u"PRAGMA journal_mode = DELETE")
                journal_mode = u"DELETE"
            self._cursor.execute(u"PRAGMA page_size = 8192")
            self._cursor.execute(u"VACUUM")
            page_size = 8192

        #
        # PRAGMA journal_mode = DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        # http://www.sqlite.org/pragma.html#pragma_page_size
        #
        if __debug__: dprint("PRAGMA journal_mode = WAL (previously: ", journal_mode, ")")
        if not journal_mode == u"WAL":
            self._cursor.execute(u"PRAGMA journal_mode = WAL")

        #
        # PRAGMA synchronous = 0 | OFF | 1 | NORMAL | 2 | FULL;
        # http://www.sqlite.org/pragma.html#pragma_synchronous
        #
        if __debug__: dprint("PRAGMA synchronous = NORMAL (previously: ", synchronous, ")")
        if not synchronous in (u"NORMAL", u"1"):
            self._cursor.execute(u"PRAGMA synchronous = NORMAL")

        # check is the database contains an 'option' table
        try:
            count, = self.execute(u"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'option'").next()
        except StopIteration:
            raise RuntimeError()

        if count:
            # get version from required 'option' table
            try:
                version, = self.execute(u"SELECT value FROM option WHERE key == 'database_version' LIMIT 1").next()
            except StopIteration:
                # the 'database_version' key was not found
                version = u"0"
        else:
            # the 'option' table probably hasn't been created yet
            version = u"0"

        self._database_version = self.check_database(version)
        assert isinstance(self._database_version, (int, long)), type(self._database_version)

    @property
    def database_version(self):
        return self._database_version

    def file_path(self):
        """
        The database filename including path.
        """
        return self._file_path

    def __enter__(self):
        """
        Enters a no-commit state.  The commit will be performed by __exit__.

        @return: The method self.execute
        """
        assert self._debug_thread_ident == thread.get_ident()

        if __debug__: dprint("disabling Database.commit()")
        self._pending_commits = max(1, self._pending_commits)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Leaves a no-commit state.  A commit will be performed if Database.commit() was called while
        in the no-commit state.
        """
        assert self._debug_thread_ident == thread.get_ident()

        self._pending_commits, pending_commits = 0, self._pending_commits

        if exc_type is None:
            if __debug__: dprint("enabling Database.commit()")
            if pending_commits > 1:
                if __debug__: dprint("performing ", pending_commits - 1, " pending commits")
                self.commit()
            return True
        elif isinstance(exc_value, IgnoreCommits):
            if __debug__: dprint("enabling Database.commit() without committing now")
            return True
        else:
            if __debug__: dprint("ROLLBACK", level="error")
            self._connection.rollback()
            return False

    @property
    def last_insert_rowid(self):
        """
        The row id of the most recent insert query.
        @rtype: int or long
        """
        assert self._debug_thread_ident == thread.get_ident()
        assert not self._cursor.lastrowid is None, "The last statement was NOT an insert query"
        return self._cursor.lastrowid

    @property
    def changes(self):
        """
        The number of changes that resulted from the most recent query.
        @rtype: int or long
        """
        assert self._debug_thread_ident == thread.get_ident()
        return self._cursor.rowcount
        # return self._connection.changes()

    def execute(self, statement, bindings=()):
        """
        Execute one SQL statement.

        A SQL query must be presented in unicode format.  This is to ensure that no unicode
        exeptions occur when the bindings are merged into the statement.

        Furthermore, the bindings may not contain any strings either.  For a 'string' the unicode
        type must be used.  For a binary string the buffer(...) type must be used.

        The SQL query may contain placeholder entries defined with a '?'.  Each of these
        placeholders will be used to store one value from bindings.  The placeholders are filled by
        sqlite and all proper escaping is done, making this the preferred way of adding variables to
        the SQL query.

        @param statement: the SQL statement that is to be executed.
        @type statement: unicode

        @param bindings: the values that must be set to the placeholders in statement.
        @type bindings: tuple

        @returns: unknown
        @raise sqlite.Error: unknown
        """
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
        assert isinstance(bindings, (tuple, list, dict, set)), "The bindings must be a tuple, list, dictionary, or set"
        assert all(lambda x: isinstance(x, str) for x in bindings), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB. \nGiven types: %s" % str([type(binding) for binding in bindings])

        try:
            if __debug__: dprint(statement, " <-- ", bindings)
            return self._cursor.execute(statement, bindings)

        except sqlite3.Error:
            if __debug__:
                dprint(exception=True, level="warning")
                dprint("Filename: ", self._file_path, level="warning")
                dprint(statement, level="warning")
                dprint(bindings, level="warning")
            raise

    def executescript(self, statements):
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statements, unicode), "The SQL statement must be given in unicode"

        try:
            if __debug__: dprint(statements)
            return self._cursor.executescript(statements)

        except sqlite3.Error:
            if __debug__:
                dprint(exception=True, level="warning")
                dprint("Filename: ", self._file_path, level="warning")
                dprint(statements, level="warning")
            raise

    def executemany(self, statement, sequenceofbindings):
        """
        Execute one SQL statement several times.

        All SQL queries must be presented in unicode format.  This is to ensure that no unicode
        exeptions occur when the bindings are merged into the statement.

        Furthermore, the bindings may not contain any strings either.  For a 'string' the unicode
        type must be used.  For a binary string the buffer(...) type must be used.

        The SQL query may contain placeholder entries defined with a '?'.  Each of these
        placeholders will be used to store one value from bindings.  The placeholders are filled by
        sqlite and all proper escaping is done, making this the preferred way of adding variables to
        the SQL query.

        @param statement: the SQL statement that is to be executed.
        @type statement: unicode

        @param bindings: a sequence of values that must be set to the placeholders in statement.
         Each element in sequence is another tuple containing bindings.
        @type bindings: list containing tuples

        @returns: unknown
        @raise sqlite.Error: unknown
        """
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        if __debug__:
            # we allow GeneratorType but must convert it to a list in __debug__ mode since a
            # generator can only iterate once
            from types import GeneratorType
            if isinstance(sequenceofbindings, GeneratorType):
                sequenceofbindings = list(sequenceofbindings)
        assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
        assert isinstance(sequenceofbindings, (tuple, list, set)), "The sequenceofbindings must be a tuple, list, or set"
        assert all(isinstance(x, (tuple, list, dict, set)) for x in list(sequenceofbindings)), "The sequenceofbindings must be a list with tuples, lists, dictionaries, or sets"
        assert not filter(lambda x: filter(lambda y: isinstance(y, str), x), list(sequenceofbindings)), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB."

        try:
            if __debug__: dprint(statement)
            return self._cursor.executemany(statement, sequenceofbindings)

        except sqlite3.Error:
            if __debug__:
                dprint(exception=True)
                dprint("Filename: ", self._file_path)
                dprint(statement)
            raise

    def commit(self):
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.commit on the wrong thread"

        if self._pending_commits:
            if __debug__: dprint("defer COMMIT")
            self._pending_commits += 1
            return False

        else:
            if __debug__: dprint("COMMIT")
            result = self._connection.commit()
            for callback in self._commit_callbacks:
                try:
                    callback()
                except Exception:
                    if __debug__: dprint(exception=True, stack=True)
            return result

    # def _on_rollback(self):
    #     if __debug__: dprint("ROLLBACK", level="warning")
    #     raise DatabaseRollbackException(1)

    def check_database(self, database_version):
        """
        Check the database and upgrade if required.

        This method is called once for each Database instance to ensure that the database structure
        and version is correct.  Each Database must contain one table of the structure below where
        the database_version is stored.  This value is used to keep track of the current database
        version.

        >>> CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
        >>> INSERT INTO option(key, value) VALUES('database_version', '1');

        @param database_version: the current database_version value from the option table. This
         value reverts to u'0' when the table could not be accessed.
        @type database_version: unicode
        """
        raise NotImplementedError()

    def attach_commit_callback(self, func):
        assert not func in self._commit_callbacks
        self._commit_callbacks.append(func)

    def detach_commit_callback(self, func):
        assert func in self._commit_callbacks
        self._commit_callbacks.remove(func)
