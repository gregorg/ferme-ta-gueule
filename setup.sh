#!/bin/bash

set -e

git pull

if [ -e ~/.poetry/env ]
then
    source ~/.poetry/env
elif ! which poetry >/dev/null
then
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
    source ~/.poetry/env
fi

poetry install

echo
echo
echo
echo "✓ OK ! Now run it with: "
echo "🦄 source ~/.poetry/env && poetry run ftg"
