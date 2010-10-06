from Database import Database

def main():
    class DB(Database):
        def check_database(self, database_version):
            pass

    def rh():
        print "rh"
        raise RuntimeError("foo")

    db = DB(u":memory:")
    db.execute(u"create table foo(x)")
    db._connection.setrollbackhook(rh)

    try:
        db.execute(u"begin ; insert into foo values(10); end;");
    except RuntimeError:
        print "runtime error"

if __name__ == "__main__":
    main()

