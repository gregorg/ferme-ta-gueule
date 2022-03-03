#!/bin/bash

set -e

# -q param to skip ftg updates
if [ "$1" = "-q" ]
then 
    shift 1
else
    ./setup.sh
fi
source ~/.poetry/env
poetry run ftg $@
