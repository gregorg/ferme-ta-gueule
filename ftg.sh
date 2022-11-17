#!/bin/bash

set -e

cd $( dirname $0 )

# -q param to skip ftg updates
if [ "$1" = "-q" ]
then 
    shift 1
else
    ./setup.sh
fi

if [ -e ~/.poetry/env ]
then
    source ~/.poetry/env
fi
poetry run ftg $@
