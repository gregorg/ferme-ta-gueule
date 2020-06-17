FROM debian:buster-slim

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install python3 python3-pip \
    && apt-get clean

WORKDIR /scripts

RUN python3 -m pip install -U pip setuptools
ENTRYPOINT ["/usr/bin/python3", "./ferme-ta-gueule.py"]

# minimize layers updates
COPY requirements.txt .
RUN python3 -m pip install -U pip \
    && python3 -m pip install -r requirements.txt --user

# should be last:
COPY . .



