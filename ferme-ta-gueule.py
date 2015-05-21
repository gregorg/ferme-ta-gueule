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

class ColoredFormatter(logging.Formatter): # {{{
    COLORS = {
        'WARNING': 'yellow',
        'INFO': 'cyan',
        'CRITICAL': 'white',
        'ERROR': 'red'
    }
    ON_COLORS = {
        'CRITICAL': 'on_red',
        'ERROR': 'on_yellow'
    }
    COLORS_ATTRS = {
        'CRITICAL': ('bold',),
    }

    def __init__(self, use_color = True):
        # main formatter:
        logformat = u'%(asctime)s %(levelname)-8s %(message)s'
        logdatefmt = '%H:%M:%S %d/%m/%Y'
        logging.Formatter.__init__(self, logformat, logdatefmt)

        self.use_color = use_color
        if self.use_color and not 'termcolor' in sys.modules:
            try:
                import termcolor
            except:
                self.use_color = False
                logging.debug("You could activate colors with 'termcolor' module")

    def format(self, record):
        if self.use_color and record.levelname in self.COLORS:
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

def getTerminalSize():
    rows, columns = os.popen('stty size', 'r').read().split()
    return (rows, columns)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", help="Do not truncate output", action="store_true")
    parser.add_argument("--error", help="Only errors", action="store_true")
    parser.add_argument("--fatal", help="Only fatals", action="store_true")
    parser.add_argument("--notice", help="Only notices", action="store_true")
    parser.add_argument("--grep", help="grep pattern. Use /pattern/ for regex search.", action="store")
    args = parser.parse_args()

    es = elasticsearch.Elasticsearch(
        url, 
        use_ssl=True,
        verify_certs=False
    )

    logging.getLogger('elasticsearch').setLevel(logging.WARNING)
    loghandler = logging.StreamHandler()
    loghandler.setFormatter(ColoredFormatter(True))
    logs = logging.getLogger('logs')
    while len(logs.handlers) > 0:
        logs.removeHandler(logs.handlers[0])

    logs.addHandler(loghandler)
    logs.setLevel(logging.DEBUG)

    logs.info("%d logs in ElasticSearch index", es.count(INDEX)['count'])

    if args.notice:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.DEBUG])
    elif args.error:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.ERROR])
    elif args.fatal:
        level = " ".join([k for k, v in LEVELSMAP.items() if v == logging.CRITICAL])


    now = int(time.time()) - 3600*2
    lasts = []
    stats = {'levels': {}}
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

                    if not ids['_id'] in lasts:
                        prettydate = datetime.datetime.fromtimestamp(newnow).strftime('%d-%m-%Y %H:%M:%S')
                        loglvl = ids['_source']['level']

                        logmsg = ids['_source']['msg']
                        if not args.full:
                            logmsg = logmsg[:200]

                        msg = "[%s] <%s> %s >> %s"%(prettydate, ids['_source']['level'], ids['_source']['program'], logmsg)

                        try:
                            logs.log(LEVELSMAP[loglvl], msg)
                        except KeyError:
                            logs.log(logging.DEBUG, msg)
                            


                        try:
                            stats['levels'][ids['_source']['level']] += 1
                        except KeyError:
                            stats['levels'][ids['_source']['level']] = 1

                    if newnow == now:
                        if not ids['_id'] in lasts:
                            lasts.append(ids['_id'])
                    else:
                        lasts = [ids['_id']]

                    now = newnow
            time.sleep(0.2)
    except KeyboardInterrupt: pass
