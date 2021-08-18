#!/bin/bash

set -e

git pull

if ! which poetry >/dev/null
then
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | POETRY_HOME=/usr/local/poetry python3
fi

poetry install

echo
echo
echo
echo "✓ OK ! Now run it with: "
echo "🦄 poetry run ftg"
