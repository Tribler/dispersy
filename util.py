# util.py ---
#
# Filename: util.py
# Description:
# Author: Elric Milon
# Maintainer:
# Created: Thu May  1 18:34:26 2014 (+0200)

# Commentary:
#
# Misc utility code
#
#

# Change Log:
#
#
#
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.
#
#

# Code:
from twisted.internet import reactor
from twisted.internet.threads import blockingCallFromThread
from twisted.python.threadable import isInIOThread

#Various decorators

def call_on_reactor_thread(func):
    def helper(*args, **kargs):
        if isInIOThread():
            return func(*args, **kargs)
        else:
            return blockingCallFromThread(reactor, func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


#
# util.py ends here
