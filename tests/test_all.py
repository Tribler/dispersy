#!/usr/bin/env python
# Python 2.5 features
from __future__ import with_statement

import sys
import os

from tempfile import mkdtemp
from shutil import rmtree

import unittest
from ..tool.main import main_real

TMPDIR='dispersy_tests_temp_dir'

def dispersyTest(callable_):
    """
    Decorator that calls the test named like the method name from dispersy.script.*
    """
    assert(callable_.__name__.startswith('test'))
    name = callable_.__name__[4:]
    #Ugly hack to otain the working copy dir name
    #this file is at [...]/BRANCH_NAME/tests/test_all.py and we want to obtain BRANCH_NAME
    working_copy_dirname = __file__.split(os.sep)[-3]
    script='%s.script.%s' % (working_copy_dirname, name)
    def caller(self):
        sys.argv = ['', '--script', script, '--statedir', mkdtemp(suffix=name, dir=TMPDIR)]
        callback = main_real()
        if callback.exception:
            raise type(callback.exception), callback.exception
    caller.__name__ = callable_.__name__
    return caller

class TestDispersyBatch(unittest.TestCase):
    def __init__(self, methodname='runTest'):
        unittest.TestCase.__init__(self, methodname)

    def setUp(self):
        if not os.path.exists(TMPDIR):
            os.makedirs(TMPDIR)

    def tearDown(self):
        try:
            rmtree(TMPDIR)
        except:
            pass

    @dispersyTest
    def testDispersyBatchScript(self):
        pass
    @dispersyTest
    def testDispersyBootstrapServers(self):
        pass

    @dispersyTest
    def testDispersyClassificationScript(self):
        pass

    @dispersyTest
    def testDispersyCryptoScript(self):
        pass

    @dispersyTest
    def testDispersyDestroyCommunityScript(self):
        pass
    @dispersyTest
    def testDispersyDynamicSettings(self):
        pass
    @dispersyTest
    def testDispersyIdenticalPayloadScript(self):
        pass

    @dispersyTest
    def testDispersyMemberTagScript(self):
        pass

    @dispersyTest
    def testDispersyMissingSequenceScript(self):
        pass

    @dispersyTest
    def testDispersyMissingMessageScript(self):
        pass

    @dispersyTest
    def testDispersySignatureScript(self):
        pass

    @dispersyTest
    def testDispersySyncScript(self):
        pass

    @dispersyTest
    def testDispersyTimelineScript(self):
        pass

    @dispersyTest
    def testDispersyUndoScript(self):
        pass
