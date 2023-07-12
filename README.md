# ferme-ta-gueule

Live logs streamer from ElasticSearch cluster.

![Ferme_ta_gueule_by_Katikut](http://fc09.deviantart.net/fs48/f/2009/226/3/f/Ferme_ta_gueule_by_Katikut.jpg)

## Quick run from Docker images

Images available for OSX and Linux OS.

```
docker run --rm -it ghcr.io/gregorg/ferme-ta-gueule:master
```

## Quick install

Run:
```
./setup.sh
```

## Or install Poetry and deps

```
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## Enjoy

```
poetry run ftg
```

### Exclude on programs

```
poetry run ftg --program '!signup,!fix-location'
```

### Grep strings

With Python regex (not ElasticSearch) :

```
poetry run ftg --grep "string"
```

## With Docker

```
docker build -t ftg .
docker run -it ftg
```

