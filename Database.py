import thread
import apsw

from .Singleton import Singleton

class Database(Singleton):
    def __init__(self, file_path):
        if __debug__:
            self._thread_ident = thread.get_ident()

        self._connection = apsw.Connection(file_path)
        self._cursor = self._connection.cursor()

    def get_cursor(self):
        assert self._thread_ident == thread.get_ident()
        return self._cursor
    
