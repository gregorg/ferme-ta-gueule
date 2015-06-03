#!/bin/bash


sudo=
pysetupargs="--user"
if [ $( id -u ) -gt 0 ]
then
	sudo="sudo"
fi

if which apt-get >/dev/null
then
	$sudo apt-get install python-setuptools python-pip
elif which brew >/dev/null
then
	pysetupargs=
	if ! which python >/dev/null
	then
		$sudo brew install python
	fi
fi

set -e

cd /tmp
git clone https://github.com/gregorg/ferme-ta-gueule.git
cd ferme-ta-gueule
python setup.py install $pysetupargs

