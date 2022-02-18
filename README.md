# ferme-ta-gueule

Live logs streamer from ElasticSearch cluster.

![Ferme_ta_gueule_by_Katikut](http://fc09.deviantart.net/fs48/f/2009/226/3/f/Ferme_ta_gueule_by_Katikut.jpg)

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

## With Docker

```
docker build -t ftg .
docker run -it ftg
```

