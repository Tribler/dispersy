# __init__.py ---
#
# Filename: __init__.py
# Description:
# Author: Elric Milon
# Maintainer:
# Created: Fri Jun 10 10:26:11 2016 (+0200)

# Commentary:
#
#
#
#

# Change Log:
#
#
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Emacs.  If not, see <http://www.gnu.org/licenses/>.
#
#

# Code:

import sys

# Do not (re)move the reactor import, even if we aren't using it
# (nose starts the reactor in a separate thread when importing this)\
if "twisted.internet.reactor" in sys.modules.keys():
    """ Tribler already imported the reactor. """
    from twisted.internet import reactor
else:
    from nose.twistedtools import reactor

#
# __init__.py ends here
