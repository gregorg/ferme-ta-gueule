#!/usr/bin/env python3
# vim: ai ts=4 sts=4 et sw=4

import os
import sys
import time
import datetime
import copy
import termcolor
import subprocess
import cmd
import threading
import re

import argparse

# Force elasticsearch package version
import pkg_resources

pkg_resources.require("elasticsearch>=7.5.0")
import elasticsearch

from pprint import pprint

# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
import urllib3
# urllib3.disable_warnings()
import logging

logging.captureWarnings(True)

url = 'https://elasticsearch.easyflirt.com:443'
LEVELSMAP = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARN': logging.WARNING,
    'warning': logging.WARNING,
    'WARNING': logging.WARNING,
    'err': logging.ERROR,
    'alert': logging.ERROR,
    'ERROR': logging.ERROR,
    'ALERT': logging.CRITICAL,
    'FATAL': logging.CRITICAL,
    'CRITICAL': logging.CRITICAL,
    'EMERGENCY': logging.CRITICAL,
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
    'ERROR': 'on_red',
}
COLORS_ATTRS = {
    'CRITICAL': ('bold',),
    'WARNING': ('bold',),
    'ERROR': ('bold',),
    'DEBUG': ('dark',),
}


class TimePrecisionException(Exception): pass


class FtgShell(cmd.Cmd):
    prompt = '🚨 '

    def __init__(self, ftg, event):
        super().__init__()
        self.event = event
        self.ftg = ftg

    def do_enable(self, arg):
        """enable "progress\""""
        if arg == 'progress':
            self.ftg.set_progress(True)

    def do_disable(self, arg):
        """disable "progress\""""
        if arg == 'progress':
            self.ftg.set_progress(False)

    def do_debug(self, arg):
        'debug'
        debug = self.ftg.get_debug()
        pprint(debug)

    def do_ls(self, arg):
        """list available indices"""
        for ind in self.ftg.list():
            print("- " + ind)

    def do_index(self, arg):
        """set index"""
        self.ftg.set_index(arg)

    def do_id(self, arg):
        """print details for an Id"""
        doc = self.ftg.get_id(arg)
        if doc:
            print("👀 ID #%s :" % (arg,))
            for k, v in doc['_source'].items():
                print("%-14s: %s" % (k, v))

    def do_from(self, arg):
        """from "12" seconds or "3h" hours"""
        if 'h' in arg:
            h = re.match(r'^\d+', arg).group(0)
            self.ftg.set_from(int(time.time()) - (int(h) * 3600))
        else:
            self.ftg.set_from(int(time.time()) - int(arg))

    def do_grep(self, arg):
        """add a pattern to grep"""
        self.ftg.grep(arg)

    def do_host(self, arg):
        """add a host"""
        self.ftg.host(arg)

    def do_purge(self, arg):
        """purge logs"""
        self.ftg.purge()

    def do_tag(self, arg):
        """add a tag"""
        self.ftg.tag(arg)

    def do_program(self, arg):
        """add a program"""
        self.ftg.program(arg)

    def do_reset(self, arg):
        """reset all filters"""
        self.ftg.set_min_level(logging.DEBUG)
        self.ftg.reset()

    def do_level(self, arg):
        """set level to: notice|error|warn|info|fatal"""
        if arg == 'notice':
            self.ftg.set_level(logging.DEBUG)
        elif arg == 'error':
            self.ftg.set_min_level(logging.ERROR)
        elif arg == 'warn':
            self.ftg.set_min_level(logging.WARNING)
        elif arg == 'info':
            self.ftg.set_min_level(logging.INFO)
        elif arg == 'fatal':
            self.ftg.set_level(logging.CRITICAL)
        else:
            print("Log level unknown")

    def do_q(self, arg):
        """exit"""
        self.event.set()
        return True
    
    def do_pause(self, arg):
        """pause"""
        self.ftg.pause()

    def do_resume(self, arg):
        """resume"""
        self.ftg.resume()

    def emptyline(self):
        pass

class Ftg:
    MAX_PACKETS = 1000

    def __init__(self, url, interval, progress):
        self.url = url
        self.masked_url = re.sub(r':[^/].*?@', ':******@', self.url)
        self.interval = interval
        self.levels = None
        self.es_index = None
        self.now = time.time() - 60
        self.last_timestamp = None
        self.datefield = "timestamp"
        self.lasts = []
        self.shell_event = None
        self.stats = {'levels': {}}
        self.laststats = time.time()
        self.progress = progress
        self.query_ids = []
        self.query = {}
        self.pause_event = threading.Event()

        self.es = elasticsearch.Elasticsearch(
            self.url,
            use_ssl=("https://" in self.url),
            retry_on_timeout=True,
            max_retries=0
        )

        logging.getLogger('elasticsearch').setLevel(logging.WARNING)
        loghandler = logging.StreamHandler(sys.stdout)
        # loghandler.setFormatter(ColoredFormatter())
        self.logger = logging.getLogger('logs')
        while len(self.logger.handlers) > 0:
            self.logger.removeHandler(self.logger.handlers[0])
        self.logger.addHandler(loghandler)
        self.logger.setLevel(logging.DEBUG)

    def get_debug(self):
        return {
            'progress': self.progress,
            'index': self.es_index,
            'url': self.masked_url,
            'now': self.now,
            'levels': self.levels,
            'query': self.query,
            'last_timestamp': self.last_timestamp
        }

    def set_progress(self, p):
        self.progress = p

    def set_index(self, index):
        self.es_index = index
        ftg.logger.info("[%s] %d logs in ElasticSearch index %s", self.masked_url, self.es.count(index=self.es_index)['count'],
                        self.es_index)

    def purge(self):
        try:
            cleanup = self.es.delete_by_query(
                index=self.es_index,
                body={"query": {"range": {"date": {"lt": "now-30d"}}}},
            )
            if cleanup['deleted'] > 0:
                ftg.logger.info("%s: %d logs deleted (PURGED).", self.es_index, cleanup['deleted'])
            # search TTLs
            search_ttls = self.es.search(index=self.es_index,
                                         body={"size": 0, "aggs": {"distinct_ttl": {"terms": {"field": "ttl"}}}})
            # for each TTLs, delete by query
            for res_ttl in search_ttls['aggregations']['distinct_ttl']['buckets']:
                ttl = res_ttl['key']
                matches = re.search(r'(\d+)([dh])', ttl)
                ttl_in_sec = None
                try:
                    ttl_in_sec = int(ttl)
                except ValueError:
                    pass
                if matches:
                    if matches.group(2) == "d":
                        ttl_in_sec = int(matches.group(1)) * 86400
                    elif matches.group(2) == "h":
                        ttl_in_sec = int(matches.group(1)) * 3600
                    ftg.logger.debug("TTL is %d%s -> %d", int(matches.group(1)), matches.group(2), ttl_in_sec)

                ftg.logger.debug("Cleaning up %s: %s (%ds)", self.es_index, ttl, ttl_in_sec)

                cleanup = self.es.delete_by_query(
                    index=self.es_index,
                    body={"query":
                        {
                            "bool": {
                                "must": [
                                    {"range": {"date": {"lt": int((time.time() - ttl_in_sec) * 1000)}}},
                                    {"match": {"ttl": ttl}}
                                ]
                            }}
                    }
                )
                if cleanup['deleted'] > 0:
                    ftg.logger.info("%s: %d logs deleted.", self.es_index, cleanup['deleted'])

        except elasticsearch.exceptions.ConnectionError:
            ftg.logger.warning("Unable to cleanup %s: not connected", self.es_index, exc_info=False)
        except elasticsearch.exceptions.ConflictError:
            ftg.logger.warning("%s: ES conflict error in cleanup", self.es_index, exc_info=True)
        except Exception as e:
            ftg.logger.warning("Unable to cleanup %s", self.es_index, exc_info=True)

    def list(self):
        indices = []
        for index in self.es.indices.get("*"):
            s = self.es.search(body={"query": {"bool": {"must": {"wildcard": {"program": "*"}}}}}, index=index, size=1)
            if s['hits']['total']['value'] > 0:
                indices.append(index)
        return indices

    def get_id(self, id):
        tries = 1
        while True:
            try:
                return self.es.get(index=self.es_index, id=id)
                break
            except elasticsearch.exceptions.NotFoundError:
                if tries >= 4:
                    return None
                else:
                    tries += 1

    def set_level(self, level):
        self.levels = [k for k, v in LEVELSMAP.items() if v == level]
        self.set_levels()

    def set_min_level(self, level):
        if level == logging.DEBUG:
            self.levels = None
        else:
            self.levels = [k for k, v in LEVELSMAP.items() if v >= level]
        self.set_levels()

    def set_levels(self):
        if self.levels:
            levels_query = {"bool": {"should": [], "minimum_should_match": 1}}
            for level in self.levels:
                levels_query['bool']['should'].append({"match_phrase": {"level": level}})
            try:
                self.query['query']['bool']['must'].append(levels_query)
            except KeyError:
                self.query['query']['bool']['must'] = [levels_query]

    def set_from(self, now):
        self.now = now

    def prepare(self):
        self.query = {"query": {"bool": {"filter": {"range": {self.datefield: {"gte": self.now}}}}}}
        self.set_levels()

    def reset(self):
        try:
            del self.query['query']['bool']['must']
        except KeyError:
            pass

    def grep(self, pattern):
        grep = self.pattern_to_es(pattern)
        try:
            self.query['query']['bool']['must'].append({'query_string': {'fields': ['msg'], 'query': grep}})
        except KeyError:
            self.query['query']['bool']['must'] = [({'query_string': {'fields': ['msg'], 'query': grep}})]

    def exclude(self, exclude):
        try:
            self.query['query']['bool']['must_not'].append(
                {'query_string': {'fields': ['msg'], 'query': self.pattern_to_es(exclude)}})
        except KeyError:
            self.query['query']['bool']['must_not'] = [
                ({'query_string': {'fields': ['msg'], 'query': self.pattern_to_es(exclude)}})]
        self.query['query']['bool']['must_not'].append({'query_string': {'fields': ['program'], 'query': exclude}})

    def program(self, program):
        try:
            self.query['query']['bool']['must'].append({'query_string': {'fields': ['program'], 'query': program}})
        except KeyError:
            self.query['query']['bool']['must'] = [({'query_string': {'fields': ['program'], 'query': program}})]

    def tag(self, tag):
        try:
            self.query['query']['bool']['must'].append({'query_string': {'fields': ['msg'], 'query': "\t%s \-" % tag}})
        except KeyError:
            self.query['query']['bool']['must'] = [({'query_string': {'fields': ['msg'], 'query': "\t%s \-" % tag}})]

    def host(self, host):
        try:
            self.query['query']['bool']['must'].append({'query_string': {'fields': ['host'], 'query': host}})
        except KeyError:
            self.query['query']['bool']['must'] = [({'query_string': {'fields': ['host'], 'query': host}})]

    def pattern_to_es(self, pattern):
        if not pattern.startswith('/') and not pattern.startswith('*') and not pattern.endswith('*'):
            pattern = '*' + pattern + '*'
            return pattern.replace(" ", '* AND *')
        else:
            return pattern.replace(" ", ' AND ')

    def rebuild_query(self, oldfield, newfield):
        for k, v in self.query.items():
            if isinstance(v, dict):
                self.rebuild_query(v, oldfield, newfield)
            if k == oldfield:
                k = k.replace(oldfield, newfield)
                self.query[k] = v
                del self.query[oldfield]

    def get_terminal_width(self):
        try:
            stty = os.popen('stty size', 'r')
            tty_rows, tty_columns = stty.read().split()
            return int(tty_columns)
        except:
            self.logger.warning("Unable to guess terminal size")
            return False
        finally:
            try:
                stty.close()
            except: pass

    def get_datetime(self, field):
        # 2016-06-03T12:02:53+0000
        # 2019-11-27T12:39:40.609424+00:00
        for format in ("%Y-%m-%dT%H:%M:%S+0000", "%Y-%m-%dT%H:%M:%S.%f+00:00"):
            try:
                return datetime.datetime.strptime(field, format)
            except:
                pass
        return None

    def set_shell_event(self, event):
        self.shell_event = event
        
    def pause(self):
        self.pause_event.set()

    def resume(self):
        self.pause_event.clear()
        
    def loop(self):
        self.logger.debug("ES query: %s" % self.query)
        tty_columns = self.get_terminal_width()
        maxp = self.MAX_PACKETS
        progress = self.progress

        try:
            while True:
                try:
                    if self.shell_event.is_set():
                        break
                    if self.pause_event.is_set():
                        time.sleep(0.2)
                        continue
                    # sys.stdout.write('#')
                    # sys.stdout.flush()
                    if isinstance(self.now, int):
                        self.query['query']['bool']['filter']['range'][self.datefield]['gte'] = self.now
                    else:
                        self.query['query']['bool']['filter']['range'][self.datefield]['gte'] = self.now
                    try:
                        if maxp > 10000:
                            maxp = 10000
                        s = self.es.search(body=self.query, sort="%s:asc" % self.datefield, index=self.es_index, size=maxp)
                    except elasticsearch.exceptions.ConnectionError:
                        self.logger.warning("ES connection error, retry in 1sec ...", exc_info=False)
                        time.sleep(1)
                        continue
                    except elasticsearch.exceptions.RequestError as e:
                        if 'No mapping found for' in str(e.info):
                            self.datefield = "datetime"
                            self.rebuild_query("timestamp", self.datefield)
                            self.now = datetime.datetime.now() - datetime.timedelta(
                                hours=self._from if self._from is not None else 1)
                            self.query['query']['bool']['filter']['range'][self.datefield]['gte'] = self.get_datetime(
                                now)
                        else:
                            self.logger.critical("Elasticsearch request error, will retry again in 1s ...",
                                                 exc_info=True)
                            time.sleep(1)
                        continue
                    except (elasticsearch.exceptions.TransportError, elasticsearch.exceptions.NotFoundError,
                            elasticsearch.exceptions.ConnectionError):
                        self.logger.critical("Elasticsearch is unreachable, will retry again in 1s ...", exc_info=True)
                        time.sleep(1)
                        self.now = int(time.time()) - 60
                        continue

                    try:
                        self.last_timestamp = int(s['hits']['hits'][-1]['_source'][self.datefield])
                    except IndexError:
                        time.sleep(self.interval)
                        continue
                    except ValueError:
                        self.last_timestamp = get_datetime(s['hits']['hits'][-1]['_source'][self.datefield])
                        if self.last_timestamp is None:
                            self.logger.critical("Can't parse date: %s",
                                                 s['hits']['hits'][-1]['_source'][self.datefield])
                            sys.exit(1)

                    if self.last_timestamp <= self.now:
                        if progress:
                            if self.progress:
                                sys.stdout.write('.')
                                sys.stdout.flush()
                        else:
                            if time.time() - self.laststats >= 60:
                                self.laststats = time.time()
                                try:
                                    idx_count = self.es.count(index=self.es_index)['count']
                                    statsmsg = 'STATS: %d logs, ' % idx_count
                                    for l in self.stats['levels'].keys():
                                        statsmsg += "%s=%d, " % (l, self.stats['levels'][l])
                                    self.logger.info(statsmsg[:-2])
                                except elasticsearch.exceptions.ConnectionError:
                                    self.logger.warning(
                                        "ElasticSearch connection error, waiting 1sec before to try again...",
                                        exc_info=False)
                                    time.sleep(1)
                                    continue
                        progress = True
                        # self.logger.debug("sleep %d ... %s <=> %s | %d results, max=%d", self.interval, self.now, s['hits']['hits'][-1]['_source'][self.datefield], s['hits']['total'], maxp)
                        try:
                            total = s['hits']['total']['value']
                        except TypeError:
                            total = s['hits']['total']
                        if total >= maxp:
                            maxp += self.MAX_PACKETS
                        else:
                            time.sleep(self.interval)
                    else:
                        if progress:
                            progress = False
                            if self.progress:
                                sys.stdout.write("\n")
                        query_ids = []
                        for ids in s['hits']['hits']:
                            try:
                                newnow = ids['_source'][self.datefield]
                                try:
                                    if newnow > 1470000000000 and self.now < 1470000000000:
                                        newnow = newnow / 1000
                                        raise TimePrecisionException()
                                except TypeError:
                                    newnow = self.get_datetime(newnow)
                            except ValueError:
                                newnow = datetime.datetime.strptime(ids['_source'][self.datefield],
                                                                    "%Y-%m-%dT%H:%M:%S+0000")
                            _id = ids['_id']
                            query_ids.append(_id)

                            if not _id in self.lasts:
                                try:
                                    prettydate = datetime.datetime.fromtimestamp(newnow).strftime('%d-%m-%Y %H:%M:%S')
                                except ValueError:
                                    prettydate = datetime.datetime.fromtimestamp(newnow / 1000).strftime(
                                        '%d-%m-%Y %H:%M:%S')
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
                                # record.msg = u'%s'%termcolor.colored(record.msg, color, on_color, color_attr)
                                msg = termcolor.colored(prettydate, 'white', 'on_blue', ('bold',))
                                if 'msg' in ids['_source']:
                                    try:
                                        msg += termcolor.colored("<%s>" % ids['_source']['level'], color, on_color,
                                                                 color_attr)
                                    except KeyError:
                                        pass
                                else:
                                    try:
                                        msg += termcolor.colored("<%s>" % ids['_source']['level_name'], color, on_color,
                                                                 color_attr)
                                    except KeyError:
                                        pass
                                try:
                                    host = ids['_source']['host']
                                    msg += termcolor.colored("[%s]" % host, 'blue', None, ('bold',))
                                except:
                                    host = 'local'
                                try:
                                    msg += "(%s) %s >> " % (_id, ids['_source']['program'])
                                except KeyError:
                                    msg += "(%s) %s >> " % (_id, ids['_source']['context']['user'])
                                if not args.full and not args.short and tty_columns:
                                    logmsg = logmsg.replace("\t", "  ")[:(tty_columns - len(msg) + 44)]
                                msg += termcolor.colored(logmsg, color, on_color, color_attr)

                                self.logger.log(lvl, msg)

                                try:
                                    self.stats['levels'][ids['_source']['level']] += 1
                                except KeyError:
                                    try:
                                        self.stats['levels'][ids['_source']['level']] = 1
                                    except KeyError:
                                        pass
                            # else:
                            #    self.logger.debug("doublon: %s (%d lasts)", _id, len(self.lasts))

                            self.lasts.append(_id)

                            if newnow == self.now:
                                #self.logger.debug("now=%s %d lasts %d query_ids", self.
                                #                  now, len(self.lasts), len(query_ids))
                                # Max packets reached
                                if len(s['hits']['hits']) == maxp:
                                    maxp += self.MAX_PACKETS
                            else:
                                maxp = self.MAX_PACKETS
                                self.lasts = copy.copy(query_ids)

                            self.now = newnow
                        # time.sleep(0.1)
                        if tty_columns:
                            tty_columns = self.get_terminal_width()
                except TimePrecisionException:
                    time.sleep(1)
        except KeyboardInterrupt:
            pass


class ColoredFormatter(logging.Formatter):  # {{{

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
            record.msg = u'%s' % termcolor.colored(record.msg, color, on_color, color_attr)
        return logging.Formatter.format(self, record)


# }}}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", help="Do not truncate output", action="store_true")
    parser.add_argument("--short", help="truncate output to 200 chars (default to terminal size)", action="store_true")
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
    parser.add_argument("--tag", help="grep tag.", action="store")
    parser.add_argument("--host", help="host only", action="store")
    parser.add_argument("--index", help="specify elasticsearch index, default 'self.logger'", action="store",
                        default='logs')
    parser.add_argument("--id", help="get specific id in ES index", action="store")
    parser.add_argument("--interval", help="interval between queries, default 1s", action="store", type=float,
                        default=1)
    parser.add_argument("--url", help="Use another ES", action="store", default=url)
    parser.add_argument("--no-update", help="Update", action="store_true", default=False)
    parser.add_argument("--list", help="List indices", action="store_true", default=False)
    args = parser.parse_args()

    # Auto-update
    if not args.no_update and not args.id and not args.list:
        oldcwd = os.getcwd()
        try:
            os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
            subprocess.run(["/usr/bin/git", "pull", "origin", "master"])
            os.chdir(oldcwd)
            sys.argv.append("--no-update")
            os.execv(sys.argv[0], sys.argv)
            sys.exit(0)
        except:
            print("Update failed.")

    ftg = Ftg(args.url, args.interval, args.progress)

    if args.list:
        for ind in ftg.list():
            print("- %s" % ind)
        sys.exit(0)

    ftg.set_index(args.index)

    if args.id:
        doc = ftg.get_id(args.id)
        if doc:
            print("RESULT for ES#%s :" % (args.id,))
            for k, v in doc['_source'].items():
                print("%-14s: %s" % (k, v))
            sys.exit(0)
        else:
            print("NOT FOUND")
            sys.exit(42)

    if sys.version_info[0] < 3:
        print(">>> Python 2 is deprecated, please use Python 3 <<<")
        sys.exit(2)

    if args._from:
        ftg.set_from(int(time.time()) - 3600 * args._from)
    else:
        ftg.set_from(int(time.time()) - 60)

    ftg.prepare()

    if args.notice:
        ftg.set_min_level(logging.DEBUG)
    elif args.error:
        ftg.set_min_level(logging.ERROR)
    elif args.warn:
        ftg.set_min_level(logging.WARNING)
    elif args.info:
        ftg.set_min_level(logging.INFO)
    elif args.fatal:
        ftg.set_level(logging.CRITICAL)

    if args.grep:
        ftg.grep(args.grep)

    if args.exclude:
        ftg.exclude(args.exclude)

    if args.program:
        ftg.program(args.program)

    if args.tag:
        ftg.tag(args.tag)

    if args.host:
        ftg.host(args.host)

    shell_event = threading.Event()
    shell = FtgShell(ftg, shell_event)
    shell_thread = threading.Thread(target=shell.cmdloop)
    shell_thread.daemon = True
    shell_thread.start()
    ftg.set_shell_event(shell_event)
    ftg.loop()
