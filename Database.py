import thread
import hashlib
import apsw

from Singleton import Singleton
from Tribler.Core.Dispersy.Print import dprint

class DatabaseException(Exception):
    pass

class Database(Singleton):
    def __init__(self, file_path):
        if __debug__:
            self._thread_ident = thread.get_ident()
        assert isinstance(file_path, unicode)

        self._connection = apsw.Connection(file_path)
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

    def get_last_insert_rowid(self):
        assert self._thread_ident == thread.get_ident()
        return self._connection.last_insert_rowid()

    def screen_dump(self, tables=[]):
        """
        Dumps the content of TABLES to the console.
        """
        assert isinstance(tables, (tuple, list))
        assert not filter(lambda x: not isinstance(x, unicode), tables)
        def get_tables(tables):
            return tables or [table for table, in self._cursor.execute(u"SELECT name FROM sqlite_master WHERE tyupe = 'table' ORDER BY name")]

        def get_type(type_):
            if isinstance(type_, unicode):
                upper_type = type_.upper()
                if upper_type in all_types:
                    format_ = all_types[upper_type]
                    if isinstance(format_, unicode):
                        format_ = all_types[format_]
                    return upper_type, format_[0], format_[1]

            print "(Warning: unknown type %s)" % repr(type_)
            return u"UNKNOWN", all_types[u"UNKNOWN"][0], all_types[u"UNKNOWN"][1]

        def print_string(length, string, postfix=".."):
            if len(string) > length:
                return string[:length-len(postfix)] + postfix
            else:
                return string

        def print_blob(length, blob):
            s = str(blob)
            if s.isdigit():
                return s
            else:
                return "%s.%s" % (len(s), hashlib.sha1(s).digest().encode("HEX"))

        all_types = {u"INTEGER":(7, lambda x: print_string(7, str(x))),
                     u"NUMERIC":u"INTEGER",
                     u"INT":u"INTEGER",
                     u"TEXT":(30, lambda x: print_string(30, 'u"%s"' % x)),
                     u"STRING":u"TEXT",
                     u"STR":u"TEXT",
                     u"BLOB":(45, lambda x: print_blob(45, x)),
                     u"UNKNOWN":(30, lambda x: print_string(30, 'u"%s"' % repr(x)))}

        for table in get_tables(tables):
            row_count = self._cursor.execute(u"SELECT COUNT(1) FROM " + table).next()[0]                       

            print
            print "-- table: %s (%d) --" % (table, row_count)

            try:
                iterator = self._cursor.execute(u"SELECT * FROM " + table + u" LIMIT 100")                     
                description = self._cursor.getdescription()                                                    

                types = [get_type(type_) for _, type_ in description]                                                    
                pattern = u"  ".join([u"%"+str(width)+u"s" for _, width, _ in types])

                print pattern % tuple([type_[:width] for (type_, width, _) in types])
                print pattern % tuple([name[:width] for (_, width, _), (name, _) in zip(types, description)])  
                for row in iterator:                                                                           
                    print pattern % tuple([filter_(value) for (_, _, filter_), value in zip(types, row)])         
            except:                                                                                            
                if row_count > 0:                                                                              
                    raise                                                                                      

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
        raise NotImplemented
    
