#!/usr/bin/env python

import sys
import time
import datetime
import termcolor

try:
	import argparse
except ImportError:
	print "Please install argparse: pip install argparse --user"
try:
	import elasticsearch
except ImportError:
	print "Please install elasticsearch: pip install elasticsearch --user"

from pprint import pprint

# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
import urllib3
#urllib3.disable_warnings()
import logging
logging.captureWarnings(True)

level = None
INDEX = 'logs'
url = 'https://elasticsearch.easyflirt.com:443'

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

if __name__ == '__main__':
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
	now = int(time.time()) - 3600*2
	lasts = []
	stats = {'levels': {}}
	progress = False
	#level = 'FATAL'
	query = {"filter": {"range": {"timestamp": {"gte": now}}}}
	if level:
		query['query'] = {'match': {'level': level}}
		level -= 60

	try:
		while True:
			query['filter']['range']['timestamp']['gte'] = now
			s = es.search(INDEX, body=query, sort="timestamp:asc", size=100)
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
					sys.stdout.write("\n")
				for ids in s['hits']['hits']:
					newnow = int(ids['_source']['timestamp'])

					if not ids['_id'] in lasts:
						prettydate = datetime.datetime.fromtimestamp(newnow).strftime('%d-%m-%Y %H:%M:%S')
						lvl = ids['_source']['level']
						msg = "[%s] <%s> %s >> %s"%(prettydate, ids['_source']['level'], ids['_source']['program'], ids['_source']['msg'][:200])
						if lvl in ('WARN', 'warning'):
							logs.warning(msg)
						elif lvl in ('err', 'alert', 'ERROR'):
							logs.error(msg)
						elif lvl in ('FATAL', 'alert'):
							logs.critical(msg)
						else:
							logs.debug(msg)


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
