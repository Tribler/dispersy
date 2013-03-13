#!/bin/bash

set -e

#Go to the tests' dir parent
cd $(dirname $(readlink -f $0))/..

MODNAME=$(basename $PWD)
cd ..
nosetests --all-modules --traverse-namespace --cover-package=$MODNAME --cover-inclusive $MODNAME/tests/test_all.py $MODNAME/tests/test_candidates.py $*
#We could do it like this instead, it's simpler but uglier
#nosetests --all-modules --traverse-namespace --cover-package=. --cover-inclusive tests/test_all.py $*

