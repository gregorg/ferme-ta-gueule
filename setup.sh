#!/bin/bash

set -e

git pull origin master --ff-only

if [ -e ~/.poetry/env ]
then
    source ~/.poetry/env
elif ! which poetry >/dev/null
then
    curl -sSL https://install.python-poetry.org | python3 -
fi

export PATH="$HOME/.local/bin:$PATH"

poetry install

echo
echo
echo
echo "✓ OK ! Now run it with: "
echo "🦄 poetry run ftg"
