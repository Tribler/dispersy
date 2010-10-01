from DispersyDatabase import DispersyDatabase

class PrivilegeBase(object):
    class Implementation(object):
        def __init__(self, meta, community, sync=True):
            if __debug__:
                from Community import Community
                assert isinstance(meta, PrivilegeBase)
                assert isinstance(community, Community) or community == "DISABLED FOR DEBUG"
            self._meta = meta
            self._community = community

            # sync with database
            if sync:
                database = DispersyDatabase.get_instance()
                try:
                    self._database_id = database.execute(u"SELECT id FROM privilege WHERE community = ? AND name = ? LIMIT 1", (community.database_id, meta._name)).next()[0]
                except StopIteration:
                    database.execute(u"INSERT INTO privilege(community, name) VALUES(?, ?)", (community.database_id, meta._name))
                    self._database_id = database.get_last_insert_rowid()

        @property
        def meta(self):
            return self._meta

        @property
        def name(self):
            return self._meta._name

        @property
        def distribution(self):
            return self._meta._distribution

        @property
        def destination(self):
            return self._meta._destination

        @property
        def community(self):
            return self._community

        @property
        def database_id(self):
            return self._database_id

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__} name:{0.name}>".format(self)

    def __init__(self, name, distribution, destination):
        if __debug__:
            from Distribution import DistributionBase
            from Destination import DestinationBase
            assert isinstance(name, unicode)
            assert isinstance(distribution, DistributionBase)
            assert isinstance(destination, DestinationBase)
        self._name = name
        self._distribution = distribution
        self._destination = destination

    @property
    def name(self):
        return self._name

    @property
    def distribution(self):
        return self._distribution

    @property
    def destination(self):
        return self._destination

    def __str__(self):
        return "<{0.__class__.__name__} distribution:{0.distribution.__class__.__name__} destination:{0.destination.__class__.__name__} name:{0.name}>".format(self)

    def implement(self, *args, **kargs):
        return self.Implementation(self, *args, **kargs)

class PublicPrivilege(PrivilegeBase):
    """
    Privilege that everyone always has.
    """
    class Implementation(PrivilegeBase.Implementation):
        pass

class LinearPrivilege(PrivilegeBase):
    """
    Privilege with the Linear policy.
    """
    class Implementation(PrivilegeBase.Implementation):
        pass

# class TimelinePrivilege(PrivilegeBase):
#     """
#     Privilege with the Timeline policy.
#     """
#     class Implementation(PrivilegeBase.Implementation):
#         pass

