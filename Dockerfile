FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install python3 python3-pip curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/*

RUN python3 -m pip install -U pip \
    && curl -sSL https://install.python-poetry.org | POETRY_HOME=/usr/local/poetry python3 - \
    && ln -s /usr/local/poetry/bin/poetry /usr/bin/poetry \ 
    && ls -l /usr/bin/poetry /usr/local/poetry/bin/poetry

WORKDIR /scripts

ENTRYPOINT ["poetry", "run", "ftg"]

# minimize layers updates
COPY poetry.* *.toml ./
RUN poetry install --no-root \
    && rm -rf /root/.{local,cache}

# should be last:
COPY . .
