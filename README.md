# ferme-ta-gueule

Logger live d'erreurs provenant d'un cluster ElasticSearch

![Ferme_ta_gueule_by_Katikut](http://fc09.deviantart.net/fs48/f/2009/226/3/f/Ferme_ta_gueule_by_Katikut.jpg)


## Installer Poetry

```
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
```


## Puis les dépendances

```
poetry install
```

## Enjoy

```
poetry run ftg
```

## Variante avec Docker

```
docker build -t ftg .
docker run -it ftg
```

## Sécurité

L'accès à notre cluster ElasticSearch est bien évidemment protégé ...
