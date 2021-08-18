FROM debian:buster-slim

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install python3 python3-pip curl \
    && apt-get clean \
    && ln -s /usr/bin/python3 /usr/bin/python

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | POETRY_HOME=/usr/local/poetry python3 \
    && ln -s /usr/local/poetry/bin/poetry /usr/bin/poetry \ 
    && ls -l /usr/bin/poetry /usr/local/poetry/bin/poetry

WORKDIR /scripts

ENTRYPOINT ["poetry", "run", "ftg"]

# minimize layers updates
COPY poetry.* *.toml ./
RUN poetry install --no-root

# should be last:
COPY . .
