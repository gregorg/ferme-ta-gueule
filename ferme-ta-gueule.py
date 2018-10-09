#!/usr/bin/env python3
# vim: ai ts=4 sts=4 et sw=4

import os
import sys
import time
import datetime
import copy
import termcolor

import argparse

# Force elasticsearch package version
import pkg_resources
pkg_resources.require("elasticsearch>=5.5,<6.0.0")
import elasticsearch

from pprint import pprint

# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
import urllib3
#urllib3.disable_warnings()
import logging
logging.captureWarnings(True)

level = None
es_index = 'logs'
MAX_PACKETS = 1000
url = 'https://elasticsearch.easyflirt.com:443'
LEVELSMAP = {
    'INFO':     logging.INFO,
    'WARN':     logging.WARNING,
    'warning':  logging.WARNING,
    'err':      logging.ERROR,
    'alert':    logging.ERROR,
    'ERROR':    logging.ERROR,
    'FATAL':    logging.CRITICAL,
}
COLORS = {
    'DEBUG': 'white',
    'INFO': 'cyan',
    'WARNING': 'yellow',
    'ERROR': 'white',
    'CRITICAL': 'yellow',
}
ON_COLORS = {
    'CRITICAL': 'on_red',
}
COLORS_ATTRS = {
    'CRITICAL': ('bold',),
    'WARNING': ('bold',),
    'ERROR': ('bold',),
    'DEBUG': ('dark',),
}


class ColoredFormatter(logging.Formatter): # {{{

    def __init__(self):
        # main formatter:
        logformat = '%(message)s'
        logdatefmt = '%H:%M:%S %d/%m/%Y'
        logging.Formatter.__init__(self, logformat, logdatefmt)

    def format(self, record):
        if record.levelname in self.COLORS:
            color = self.COLORS[record.levelname]
            try:
                on_color = self.ON_COLORS[record.levelname]
            except KeyError:
                on_color = None
            try:
                color_attr = self.COLORS_ATTRS[record.levelname]
            except KeyError:
                color_attr = None
            record.msg = u'%s'%termcolor.colored(record.msg, color, on_color, color_attr)
        return logging.Formatter.format(self, record)

# }}}


def getTerminalSize(): # {{{
    rows, columns = os.popen('stty size', 'r').read().split()
    return (rows, columns)
# }}}


def pattern_to_es(pattern):
    if not pattern.startswith('/') and not pattern.startswith('*') and not pattern.endswith('*'):
        pattern = '*' + pattern + '*'
        return pattern.replace(" ", '* AND *')
    else:
        return pattern.replace(" ", ' AND ')


class TimePrecisionException(Exception): pass


def rebuild_query(query, oldfield, newfield):
    for k, v in query.items():
        if isinstance(v, dict):
            v = rebuild_query(v, oldfield, newfield)
        if k == oldfield:
            k = k.replace(oldfield, newfield)
            query[k] = v
            del query[oldfield]
    return query


def get_terminal_width():
    try:
        tty_rows, tty_columns = os.popen('stty size', 'r').read().split()
        return int(tty_columns)
    except:
        logs.warning("Unable to guess terminal size")
        return False



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", help="Do not truncate output", action="store_true")
    parser.add_argument("--short", help="truncate output to 200 chars", action="store_true")
    parser.add_argument("--error", help="Only errors", action="store_true")
    parser.add_argument("--fatal", help="Only fatals", action="store_true")
    parser.add_argument("--notice", help="Only notices", action="store_true")
    parser.add_argument("--warn", help="Only warnings", action="store_true")
    parser.add_argument("--info", help="Only >= INFO", action="store_true")
    parser.add_argument("--from", help="Starts from N hours ago", action="store", type=int, dest="_from")
    parser.add_argument("--progress", help="Progress bar", action="store_true")
    parser.add_argument("--grep", help="grep pattern. Use /pattern/ for regex search.", action="store")
    parser.add_argument("--exclude", help="grep pattern. Use /pattern/ for regex exclusion.", action="store")
    parser.add_argument("--program", help="grep program.", action="store")
    parser.add_argument("--index", help="specify elasticsearch index, default %s"%es_index, action="store")
    parser.add_argument("--id", help="get specific id in ES index", action="store")
    parser.add_argument("--interval", help="interval between queries, default 1s", action="store", type=float, default=1)
    parser.add_argument("--url", help="Use another ES", action="store", default=url)
    args = parser.parse_args()

    datefield = "timestamp"
    es = elasticsearch.Elasticsearch(
        args.url, 
        use_ssl=("https" in args.url),
        verify_certs=False,
        retry_on_timeout=True,
        max_retries=0
    )

    if args.index:
        es_index = args.index

    if args.id:
        tries = 1
        while True:
            try:
                doc = es.get(index=es_index, id=args.id)
                print("RESULT for ES#%s (%d tries) :" % (args.id, tries))
                for k, v in doc['_source'].items():
                    print("%-14s: %s"%(k, v))
                break
            except elasticsearch.exceptions.NotFoundError:
                if tries >= 4:
                    print("Not Found.")
                    sys.exit(42)
                else:
                    tries += 1
        sys.exit(0)

    logging.getLogger('elasticsearch').setLevel(logging.WARNING)
    loghandler = logging.StreamHandler(sys.stdout)
    #loghandler.setFormatter(ColoredFormatter())
    logs = logging.getLogger('logs')
    while len(logs.handlers) > 0:
        logs.removeHandler(logs.handlers[0])

    logs.addHandler(loghandler)
    logs.setLevel(logging.DEBUG)

    if sys.version_info[0] < 3:
        print(">>> Python 2 is deprecated, please use Python 3 <<<")
        time.sleep(4)

    logs.info("[%s] %d logs in ElasticSearch index", args.url, es.count(es_index)['count'])

    if args.notice:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.DEBUG])
    elif args.error:
        level = " ".join([k for k, v in LEVELSMAP.items() if v >= logging.ERROR])
    elif args.warn:
        level = " ".join([k for k, v in LEVELSMAP.items() if v >= logging.WARNING])
    elif args.info:
        level = " ".join([k for k, v in LEVELSMAP.items() if v >= logging.INFO])
    elif args.fatal:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.CRITICAL])


    if args._from:
        now = int(time.time()) - 3600 * args._from
    else:
        now = int(time.time()) - 60
    lasts = []
    stats = {'levels': {}}
    laststats = time.time()
    progress = False
    maxp = MAX_PACKETS
    query_ids = []
    query = {"query": {"bool": {"filter": {"range": {datefield: {"gte": now}}}}}}
    if level:
        try:
            query['query']['bool']['must'].append({'match': {'level': {'query': level, 'operator' : 'or'}}})
        except KeyError:
            query['query']['bool']['must'] = [({'match': {'level': {'query': level, 'operator' : 'or'}}})]
        now -= 60

    if args.grep:
        grep = pattern_to_es(args.grep)
            
        try:
            query['query']['bool']['must'].append({'query_string': {'fields': ['msg'], 'query': grep}})
        except KeyError:
            query['query']['bool']['must'] = [({'query_string': {'fields': ['msg'], 'query': grep}})]
        now -= 60

    if args.exclude:
        try:
            query['query']['bool']['must_not'].append({'query_string': {'fields': ['msg'], 'query': pattern_to_es(args.exclude)}})
        except KeyError:
            query['query']['bool']['must_not'] = [({'query_string': {'fields': ['msg'], 'query': pattern_to_es(args.exclude)}})]
        query['query']['bool']['must_not'].append({'query_string': {'fields': ['program'], 'query': args.exclude}})
        now -= 60

    if args.program:
        try:
            query['query']['bool']['must'].append({'query_string': {'fields': ['program'], 'query': args.program}})
        except KeyError:
            query['query']['bool']['must'] = [({'query_string': {'fields': ['program'], 'query': args.program}})]
        now -= 60

    logs.debug("ES query: %s"%query)
    tty_columns = get_terminal_width()


    try:
        while True:
            try:
                #sys.stdout.write('#')
                #sys.stdout.flush()
                if isinstance(now, int):
                    query['query']['bool']['filter']['range'][datefield]['gte'] = now
                else:
                    query['query']['bool']['filter']['range'][datefield]['gte'] = datetime.datetime.strftime(now, "%Y-%m-%dT%H:%M:%S+0000")
                try:
                    s = es.search(es_index, body=query, sort="%s:asc"%datefield, size=maxp)
                except elasticsearch.exceptions.ConnectionError:
                    logs.warning("ES connection error", exc_info=True)
                    time.sleep(1)
                    continue
                except elasticsearch.exceptions.RequestError as e:
                    if 'No mapping found for' in str(e.info):
                        datefield = "datetime"
                        query = rebuild_query(query, "timestamp", datefield)
                        now = datetime.datetime.now() - datetime.timedelta(hours=args._from if args._from is not None else 1)
                        query['query']['bool']['filter']['range'][datefield]['gte'] = datetime.datetime.strftime(now, "%Y-%m-%dT%H:%M:%S+0000")
                    else:
                        logs.critical("Elasticsearch request error, will retry again in 1s ...", exc_info=True)
                        time.sleep(1)
                    continue
                except elasticsearch.exceptions.TransportError:
                    logs.critical("Elasticsearch is unreachable, will retry again in 1s ...", exc_info=True)
                    time.sleep(1)
                    continue

                try:
                    last_timestamp = int(s['hits']['hits'][-1]['_source'][datefield])
                except IndexError:
                    time.sleep(args.interval)
                    continue
                except ValueError:
                    # 2016-06-03T12:02:53+0000
                    try:
                        last_timestamp = datetime.datetime.strptime(s['hits']['hits'][-1]['_source'][datefield], "%Y-%m-%dT%H:%M:%S+0000")
                    except:
                        logs.critical("Can't parse date: %s", s['hits']['hits'][-1]['_source'][datefield])
                        sys.exit(1)

                if last_timestamp <= now:
                    if progress:
                        if args.progress:
                            sys.stdout.write('.')
                            sys.stdout.flush()
                    else:
                        if time.time() - laststats >= 60:
                            laststats = time.time()
                            try:
                                idx_count = es.count(es_index)['count']
                                statsmsg = 'STATS: %d logs, '%idx_count
                                for l in stats['levels'].keys():
                                    statsmsg += "%s=%d, "%(l, stats['levels'][l])
                                logs.info(statsmsg[:-2])
                            except elasticsearch.exceptions.ConnectionError:
                                logs.warning("ES connection error", exc_info=True)
                                time.sleep(1)
                                continue
                    progress = True
                    #logs.debug("sleep %d ... %s <=> %s | %d results, max=%d", args.interval, now, s['hits']['hits'][-1]['_source'][datefield], s['hits']['total'], maxp)
                    if s['hits']['total'] >= maxp:
                        maxp += MAX_PACKETS
                    else:
                        time.sleep(args.interval)
                else:
                    if progress:
                        progress = False
                        if args.progress:
                            sys.stdout.write("\n")
                    query_ids = []
                    for ids in s['hits']['hits']:
                        try:
                            newnow = int(ids['_source'][datefield])
                            if newnow > 1470000000000 and now < 1470000000000:
                                now = now * 1000
                                raise TimePrecisionException()
                        except ValueError:
                            newnow = datetime.datetime.strptime(ids['_source'][datefield], "%Y-%m-%dT%H:%M:%S+0000")
                        _id = ids['_id']
                        query_ids.append(_id)

                        if not _id in lasts:
                            try:
                                prettydate = datetime.datetime.fromtimestamp(newnow).strftime('%d-%m-%Y %H:%M:%S')
                            except ValueError:
                                prettydate = datetime.datetime.fromtimestamp(newnow/1000).strftime('%d-%m-%Y %H:%M:%S')
                            except TypeError:
                                prettydate = str(newnow)
                            lvl = logging.DEBUG
                            for l in ('level_name', 'level'):
                                try:
                                    loglvl = ids['_source'][l]
                                    lvl = LEVELSMAP[loglvl]
                                except KeyError:
                                    continue

                            try:
                                logmsg = ids['_source']['msg']
                            except KeyError:
                                logmsg = ids['_source']['message']
                            if args.short:
                                logmsg = logmsg[:200]
                            elif not args.full:
                                logmsg = " ".join(logmsg.split("\n")[:2])

                            color = COLORS[logging.getLevelName(lvl)]
                            try:
                                on_color = ON_COLORS[logging.getLevelName(lvl)]
                            except KeyError:
                                on_color = None
                            try:
                                color_attr = COLORS_ATTRS[logging.getLevelName(lvl)]
                            except KeyError:
                                color_attr = None
                            #record.msg = u'%s'%termcolor.colored(record.msg, color, on_color, color_attr)
                            msg = termcolor.colored(prettydate, 'white', 'on_blue', ('bold',))
                            if 'msg' in ids['_source']:
                                try:
                                    msg += termcolor.colored("<%s>"%ids['_source']['level'], color, on_color, color_attr)
                                except KeyError: pass
                            else:
                                try:
                                    msg += termcolor.colored("<%s>"%ids['_source']['level_name'], color, on_color, color_attr)
                                except KeyError: pass
                            try:
                                host = ids['_source']['host']
                                msg += termcolor.colored("[%s]"%host, 'blue', None, ('bold',))
                            except:
                                host = 'local'
                            try:
                                msg += "(%s) %s >> "%(_id, ids['_source']['program'])
                            except KeyError:
                                msg += "(%s) %s >> "%(_id, ids['_source']['context']['user'])
                            if not args.full and not args.short and tty_columns:
                                logmsg = logmsg[:(tty_columns - len(msg) + 44)]
                            msg += termcolor.colored(logmsg, color, on_color, color_attr)

                            logs.log(lvl, msg)
                                
                            try:
                                stats['levels'][ids['_source']['level']] += 1
                            except KeyError:
                                try:
                                    stats['levels'][ids['_source']['level']] = 1
                                except KeyError: pass
                        #else:
                        #    logs.debug("doublon: %s (%d lasts)", _id, len(lasts))

                        lasts.append(_id)

                        if newnow == now:
                            #logs.debug("now=%s %d lasts %d query_ids", now, len(lasts), len(query_ids))
                            # Max packets reached
                            if len(s['hits']['hits']) == maxp:
                                maxp += MAX_PACKETS
                        else:
                            maxp = MAX_PACKETS
                            lasts = copy.copy(query_ids)

                        now = newnow
                    #time.sleep(0.1)
                    if tty_columns:
                        tty_columns = get_terminal_width()
            except TimePrecisionException: pass
    except KeyboardInterrupt: pass
