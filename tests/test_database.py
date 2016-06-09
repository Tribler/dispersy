import os
import shutil
from unittest import TestCase
from tempfile import mkdtemp

from ..dispersydatabase import DispersyDatabase, DatabaseVersionTooLowError, DatabaseVersionTooHighError


class TestDatabase(TestCase):
    FILE_DIR = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
    TEST_DATA_DIR = os.path.abspath(os.path.join(FILE_DIR, u"data"))
    TMP_DATA_DIR = mkdtemp(suffix="dispersy_unit_test")

    def setUp(self):
        super(TestDatabase, self).setUp()
        if not os.path.exists(self.TMP_DATA_DIR):
            os.mkdir(self.TMP_DATA_DIR)

    def tearDown(self):
        super(TestDatabase, self).tearDown()
        # Delete the database file if not using an in-memory database.
        if os.path.exists(self.TMP_DATA_DIR):
            shutil.rmtree(self.TMP_DATA_DIR, ignore_errors=True)

    def test_unsupported_database_version(self):
        minimum_version_path = os.path.abspath(os.path.join(self.TEST_DATA_DIR, u"dispersy_v1.db"))
        tmp_path = os.path.join(self.TMP_DATA_DIR, u"dispersy.db")
        shutil.copyfile(minimum_version_path, tmp_path)

        database = DispersyDatabase(tmp_path)
        self.assertRaises(DatabaseVersionTooLowError, database.open)

    def test_upgrade_16_to_latest(self):
        minimum_version_path = os.path.abspath(os.path.join(self.TEST_DATA_DIR, u"dispersy_v16.db"))
        tmp_path = os.path.join(self.TMP_DATA_DIR, u"dispersy.db")
        shutil.copyfile(minimum_version_path, tmp_path)

        database = DispersyDatabase(tmp_path)
        database.open()
        self.assertEqual(database.database_version, 21)

    def test_upgrade_version_too_high(self):
        minimum_version_path = os.path.abspath(os.path.join(self.TEST_DATA_DIR, u"dispersy_v1337.db"))
        tmp_path = os.path.join(self.TMP_DATA_DIR, u"dispersy.db")
        shutil.copyfile(minimum_version_path, tmp_path)

        database = DispersyDatabase(tmp_path)
        self.assertRaises(DatabaseVersionTooHighError, database.open)
