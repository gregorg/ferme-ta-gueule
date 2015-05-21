#!/usr/bin/env python
# vim: ai ts=4 sts=4 et sw=4

import os
import sys
import time
import datetime
import termcolor

import argparse
import elasticsearch

from pprint import pprint

# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
import urllib3
#urllib3.disable_warnings()
import logging
logging.captureWarnings(True)

level = None
INDEX = 'logs'
url = 'https://elasticsearch.easyflirt.com:443'
LEVELSMAP = {
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



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", help="Do not truncate output", action="store_true")
    parser.add_argument("--error", help="Only errors", action="store_true")
    parser.add_argument("--fatal", help="Only fatals", action="store_true")
    parser.add_argument("--notice", help="Only notices", action="store_true")
    parser.add_argument("--grep", help="grep pattern. Use /pattern/ for regex search.", action="store")
    parser.add_argument("--id", help="get specific id in ES index", action="store")
    args = parser.parse_args()

    es = elasticsearch.Elasticsearch(
        url, 
        use_ssl=True,
        verify_certs=False
    )

    if args.id:
        tries = 1
        while True:
            try:
                doc = es.get(index=INDEX, id=args.id)
                print "RESULT for ES#%s (%d tries) :" % (args.id, tries)
                for k, v in doc['_source'].items():
                    print "%-14s: %s"%(k, v)
                break
            except elasticsearch.exceptions.NotFoundError:
                if tries >= 4:
                    print "Not Found."
                    sys.exit(42)
                else:
                    tries += 1
        sys.exit(0)

    logging.getLogger('elasticsearch').setLevel(logging.WARNING)
    loghandler = logging.StreamHandler()
    #loghandler.setFormatter(ColoredFormatter())
    logs = logging.getLogger('logs')
    while len(logs.handlers) > 0:
        logs.removeHandler(logs.handlers[0])

    logs.addHandler(loghandler)
    logs.setLevel(logging.DEBUG)

    logs.info("%d logs in ElasticSearch index", es.count(INDEX)['count'])

    if args.notice:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.DEBUG])
    elif args.error:
        level = " ".join([k for k, v in LEVELSMAP.items() if v >= logging.ERROR])
    elif args.fatal:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.CRITICAL])


    now = int(time.time()) - 3600*2
    lasts = []
    stats = {'levels': {}}
    laststats = time.time()
    progress = False
    query = {"filter": {"range": {"timestamp": {"gte": now}}}}
    if level:
        try:
            query['query']['bool']['must'].append({'match': {'level': {'query': level, 'operator' : 'or'}}})
        except KeyError:
            query['query'] = {'bool': {'must': [{'match': {'level': {'query': level, 'operator' : 'or'}}}]}}
        now -= 60

    if args.grep:
        grep = args.grep
        if not grep.startswith('/') and not grep.startswith('*') and not grep.endswith('*'):
            grep = '*' + grep + '*'
            
        try:
            query['query']['bool']['must'].append({'query_string': {'fields': ['msg'], 'query': grep}})
        except KeyError:
            query['query'] = {'bool': {'must': [{'query_string': {'fields': ['msg'], 'query': grep}}]}}
        now -= 60

    logs.debug("ES query: %s"%query)

    try:
        while True:
            query['filter']['range']['timestamp']['gte'] = now
            try:
                s = es.search(INDEX, body=query, sort="timestamp:asc", size=100)
            except elasticsearch.exceptions.ConnectionError:
                time.sleep(1)
                continue

            if s['hits']['total'] <= len(lasts):
                if progress:
                    pass
                    #sys.stdout.write('.')
                    #sys.stdout.flush()
                else:
                    if time.time() - laststats >= 60:
                        laststats = time.time()
                        idx_count = es.count(INDEX)['count']
                        statsmsg = 'STATS: %d logs, '%idx_count
                        for l in stats['levels'].keys():
                            statsmsg += "%s=%d, "%(l, stats['levels'][l])
                        logs.info(statsmsg[:-2])
                progress = True
            else:
                if progress:
                    progress = False
                    #sys.stdout.write("\n")
                for ids in s['hits']['hits']:
                    newnow = int(ids['_source']['timestamp'])
                    _id = ids['_id']

                    if not _id in lasts:
                        prettydate = datetime.datetime.fromtimestamp(newnow).strftime('%d-%m-%Y %H:%M:%S')
                        loglvl = ids['_source']['level']
                        try:
                            lvl = LEVELSMAP[loglvl]
                        except KeyError:
                            lvl = logging.DEBUG

                        logmsg = ids['_source']['msg']
                        if not args.full:
                            logmsg = logmsg[:200]

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
                        msg += termcolor.colored("<%s>"%ids['_source']['level'], color, on_color, color_attr)
                        msg += "(%s) %s >> "%(_id, ids['_source']['program'])
                        msg += termcolor.colored(logmsg, color, on_color, color_attr)

                        logs.log(lvl, msg)
                            


                        try:
                            stats['levels'][ids['_source']['level']] += 1
                        except KeyError:
                            stats['levels'][ids['_source']['level']] = 1

                    if newnow == now:
                        if not _id in lasts:
                            lasts.append(_id)
                    else:
                        lasts = [_id]

                    now = newnow
            time.sleep(0.2)
    except KeyboardInterrupt: pass
