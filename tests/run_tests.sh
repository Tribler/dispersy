#!/bin/bash

set -e

unset PYTHONPATH

FILE_PATH=$(dirname $(readlink -f $0))

cd $FILE_PATH/..
MODNAME=$(basename $PWD)
cd ..

nosetests --all-modules --traverse-namespace --cover-package=$MODNAME --cover-inclusive $MODNAME/tests/test_all.py $*

