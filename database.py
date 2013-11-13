"""
This module provides basic database functionalty and simple version control.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from abc import ABCMeta, abstractmethod
from sqlite3 import Connection, Error
import logging
import sys

from .decorator import attach_runtime_statistics
from .logger import get_logger
logger = get_logger(__name__)

if __debug__:
    import thread

if "--explain-query-plan" in getattr(sys, "argv", []):
    _explain_query_plan_logger = get_logger("explain-query-plan")
    _explain_query_plan = set()

    def attach_explain_query_plan(func):
        def attach_explain_query_plan_helper(self, statements, bindings=()):
            if not statements in _explain_query_plan:
                _explain_query_plan.add(statements)

                _explain_query_plan_logger.info("Explain query plan for <<<%s>>>", statements)
                for line in self._cursor.execute(u"EXPLAIN QUERY PLAN %s" % statements, bindings):
                    _explain_query_plan_logger.info(line)
                _explain_query_plan_logger.info("--")

            return func(self, statements, bindings)
        attach_explain_query_plan_helper.__name__ = func.__name__
        return attach_explain_query_plan_helper

else:
    def attach_explain_query_plan(func):
        return func


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


class Database(object):

    __metaclass__ = ABCMeta

    def __init__(self, file_path):
        """
        Initialize a new Database instance.

        @param file_path: the path to the database file.
        @type file_path: unicode
        """
        assert isinstance(file_path, unicode)
        logger.debug("loading database [%s]", file_path)
        self._file_path = file_path

        # _CONNECTION, _CURSOR, AND _DATABASE_VERSION are set during open(...)
        self._connection = None
        self._cursor = None
        self._database_version = 0

        # _commit_callbacks contains a list with functions that are called on each database commit
        self._commit_callbacks = []

        # Database.commit() is enabled when _pending_commits == 0.  Database.commit() is disabled
        # when _pending_commits > 0.  A commit is required when _pending_commits > 1.
        self._pending_commits = 0

        if __debug__:
            self._debug_thread_ident = 0

    def open(self, initial_statements=True, prepare_visioning=True):
        assert self._cursor is None, "Database.open() has already been called"
        assert self._connection is None, "Database.open() has already been called"
        if __debug__:
            self._debug_thread_ident = thread.get_ident()
        logger.info("open database [%s]", self._file_path)
        self._connect()
        if initial_statements:
            self._initial_statements()
        if prepare_visioning:
            self._prepare_version()
        return True

    def close(self, commit=True):
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        if commit:
            self.commit(exiting=True)
        logger.info("close database [%s]", self._file_path)
        self._cursor.close()
        self._cursor = None
        self._connection.close()
        self._connection = None
        return True

    def _connect(self):
        self._connection = Connection(self._file_path)
        self._cursor = self._connection.cursor()

    def _initial_statements(self):
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"

        # collect current database configuration
        page_size = int(next(self._cursor.execute(u"PRAGMA page_size"))[0])
        journal_mode = unicode(next(self._cursor.execute(u"PRAGMA journal_mode"))[0]).upper()
        synchronous = unicode(next(self._cursor.execute(u"PRAGMA synchronous"))[0]).upper()

        #
        # PRAGMA page_size = bytes;
        # http://www.sqlite.org/pragma.html#pragma_page_size
        # Note that changing page_size has no effect unless performed on a new database or followed
        # directly by VACUUM.  Since we do not want the cost of VACUUM every time we load a
        # database, existing databases must be upgraded.
        #
        if page_size < 8192:
            logger.debug("PRAGMA page_size = 8192 (previously: %s) [%s]", page_size, self._file_path)

            # it is not possible to change page_size when WAL is enabled
            if journal_mode == u"WAL":
                self._cursor.executescript(u"PRAGMA journal_mode = DELETE")
                journal_mode = u"DELETE"
            self._cursor.execute(u"PRAGMA page_size = 8192")
            self._cursor.execute(u"VACUUM")
            page_size = 8192

        else:
            logger.debug("PRAGMA page_size = %s (no change) [%s]", page_size, self._file_path)

        #
        # PRAGMA journal_mode = DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
        # http://www.sqlite.org/pragma.html#pragma_page_size
        #
        if not (journal_mode == u"WAL" or self._file_path == u":memory:"):
            logger.debug("PRAGMA journal_mode = WAL (previously: %s) [%s]", journal_mode, self._file_path)
            self._cursor.execute(u"PRAGMA journal_mode = WAL")

        else:
            logger.debug("PRAGMA journal_mode = %s (no change) [%s]", journal_mode, self._file_path)

        #
        # PRAGMA synchronous = 0 | OFF | 1 | NORMAL | 2 | FULL;
        # http://www.sqlite.org/pragma.html#pragma_synchronous
        #
        if not synchronous in (u"NORMAL", u"1"):
            logger.debug("PRAGMA synchronous = NORMAL (previously: %s) [%s]", synchronous, self._file_path)
            self._cursor.execute(u"PRAGMA synchronous = NORMAL")

        else:
            logger.debug("PRAGMA synchronous = %s (no change) [%s]", synchronous, self._file_path)

    def _prepare_version(self):
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"

        # check is the database contains an 'option' table
        try:
            count, = next(self.execute(u"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'option'"))
        except StopIteration:
            raise RuntimeError()

        if count:
            # get version from required 'option' table
            try:
                version, = next(self.execute(u"SELECT value FROM option WHERE key == 'database_version' LIMIT 1"))
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

    @property
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
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"

        logger.debug("disabling commit [%s]", self._file_path)
        self._pending_commits = max(1, self._pending_commits)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Leaves a no-commit state.  A commit will be performed if Database.commit() was called while
        in the no-commit state.
        """
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"

        self._pending_commits, pending_commits = 0, self._pending_commits

        if exc_type is None:
            logger.debug("enabling commit [%s]", self._file_path)
            if pending_commits > 1:
                logger.debug("performing %d pending commits [%s]", pending_commits - 1, self._file_path)
                self.commit()
            return True

        elif isinstance(exc_value, IgnoreCommits):
            logger.debug("enabling commit without committing now [%s]", self._file_path)
            return True

        else:
            # Niels 23-01-2013, an exception happened from within the with database block
            # returning False to let Python reraise the exception.
            return False

    @property
    def last_insert_rowid(self):
        """
        The row id of the most recent insert query.
        @rtype: int or long
        """
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert not self._cursor.lastrowid is None, "The last statement was NOT an insert query"
        return self._cursor.lastrowid

    @property
    def changes(self):
        """
        The number of changes that resulted from the most recent query.
        @rtype: int or long
        """
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        return self._cursor.rowcount
        # return self._connection.changes()

    @attach_explain_query_plan
    @attach_runtime_statistics("{0.__class__.__name__}.{function_name} {1} [{0.file_path}]")
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
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
        assert isinstance(bindings, (tuple, list, dict, set)), "The bindings must be a tuple, list, dictionary, or set"
        assert all(lambda x: isinstance(x, str) for x in bindings), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB. \nGiven types: %s" % str([type(binding) for binding in bindings])

        logger.log(logging.NOTSET, "%s <-- %s [%s]", statement, bindings, self._file_path)
        return self._cursor.execute(statement, bindings)

    @attach_runtime_statistics("{0.__class__.__name__}.{function_name} {1} [{0.file_path}]")
    def executescript(self, statements):
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statements, unicode), "The SQL statement must be given in unicode"

        logger.log(logging.NOTSET, "%s [%s]", statements, self._file_path)
        return self._cursor.executescript(statements)

    @attach_explain_query_plan
    @attach_runtime_statistics("{0.__class__.__name__}.{function_name} {1} [{0.file_path}]")
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
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        if __debug__:
            # we allow GeneratorType but must convert it to a list in __debug__ mode since a
            # generator can only iterate once
            from types import GeneratorType
            is_iterator = isinstance(sequenceofbindings, GeneratorType)
            if is_iterator:
                sequenceofbindings = list(sequenceofbindings)
            assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
            assert isinstance(sequenceofbindings, (tuple, list, set)), "The sequenceofbindings must be a tuple, list, or set"
            assert all(isinstance(x, (tuple, list, dict, set)) for x in list(sequenceofbindings)), "The sequenceofbindings must be a list with tuples, lists, dictionaries, or sets"
            assert not filter(lambda x: filter(lambda y: isinstance(y, str), x), list(sequenceofbindings)), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB."
            if is_iterator:
                sequenceofbindings = iter(sequenceofbindings)

        logger.log(logging.NOTSET, "%s [%s]", statement, self._file_path)
        return self._cursor.executemany(statement, sequenceofbindings)

    @attach_runtime_statistics("{0.__class__.__name__}.{function_name} [{0.file_path}]")
    def commit(self, exiting=False):
        assert self._cursor is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._connection is not None, "Database.close() has been called or Database.open() has not been called"
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.commit on the wrong thread"
        assert not (exiting and self._pending_commits), "No pending commits should be present when exiting"

        if self._pending_commits:
            logger.debug("defer commit [%s]", self._file_path)
            self._pending_commits += 1
            return False

        else:
            logger.debug("commit [%s]", self._file_path)
            for callback in self._commit_callbacks:
                try:
                    callback(exiting=exiting)
                except Exception as exception:
                    logger.exception("%s [%s]", exception, self._file_path)

            return self._connection.commit()

    @abstractmethod
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
        pass

    def attach_commit_callback(self, func):
        assert not func in self._commit_callbacks
        self._commit_callbacks.append(func)

    def detach_commit_callback(self, func):
        assert func in self._commit_callbacks
        self._commit_callbacks.remove(func)


class APSWDatabase(Database):

    def _connect(self):
        import apsw
        self._connection = apsw.Connection(self._file_path)
        self._cursor = self._connection.cursor()

    def _initial_statements(self):
        super(APSWDatabase, self)._initial_statements()
        self.execute("BEGIN")

    def execute(self, statement, bindings=()):
        import apsw
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
        assert isinstance(bindings, (tuple, list, dict)), "The bindings must be a tuple, list, or dictionary"
        assert all(lambda x: isinstance(x, str) for x in bindings), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB. \nGiven types: %s" % str([type(binding) for binding in bindings])

        logger.log(logging.NOTSET, "%s <-- %s [%s]", statement, bindings, self._file_path)
        return self._cursor.execute(statement, bindings)

    def executescript(self, statements):
        return self.execute(statements)

    def executemany(self, statement, sequenceofbindings):
        import apsw
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        if __debug__:
            # we allow GeneratorType but must convert it to a list in __debug__ mode since a
            # generator can only iterate once
            from types import GeneratorType
            if isinstance(sequenceofbindings, GeneratorType):
                sequenceofbindings = list(sequenceofbindings)
        assert isinstance(statement, unicode), "The SQL statement must be given in unicode"
        assert isinstance(sequenceofbindings, (tuple, list)), "The sequenceofbindings must be a list with tuples, lists, or dictionaries"
        assert all(isinstance(x, (tuple, list, dict)) for x in list(sequenceofbindings)), "The sequenceofbindings must be a list with tuples, lists, or dictionaries"
        assert not filter(lambda x: filter(lambda y: isinstance(y, str), x), list(sequenceofbindings)), "The bindings may not contain a string. \nProvide unicode for TEXT and buffer(...) for BLOB."

        logger.log(logging.NOTSET, "%s [%s]", statement, self._file_path)
        return self._cursor.executemany(statement, sequenceofbindings)

    @property
    def last_insert_rowid(self):
        """
        The row id of the most recent insert query.
        @rtype: int or long
        """
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident()
        assert not self._cursor.lastrowid is None, "The last statement was NOT an insert query"
        return self._connection.last_insert_rowid()

    @property
    def changes(self):
        """
        The number of changes that resulted from the most recent query.
        @rtype: int or long
        """
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.execute on the wrong thread"
        return self._connection.totalchanges()

    def commit(self, exiting=False):
        assert self._debug_thread_ident != 0, "please call database.open() first"
        assert self._debug_thread_ident == thread.get_ident(), "Calling Database.commit on the wrong thread"
        assert not (exiting and self._pending_commits), "No pending commits should be present when exiting"

        logger.debug("commit [%s]", self._file_path)
        result = self.execute("COMMIT;BEGIN")
        for callback in self._commit_callbacks:
            try:
                callback(exiting=exiting)
            except Exception as exception:
                logger.debug("%s [%s]", exception, self._file_path)
        return result
