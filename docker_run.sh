#!/bin/bash


set -e
git pull
docker build -t ftg .
docker run -it ftg

