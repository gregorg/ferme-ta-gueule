#!/bin/bash

set -e

./setup.sh
source ~/.poetry/env
poetry run ftg $@
