import time
import json
import datetime
import ConfigParser
from dateutil.tz import tzlocal

Config = ConfigParser.ConfigParser()
Config.read("/opt/gatekeeper/gatekeeper.cfg")

class Rule(object):	
	def __init__(self, name, is_ssl, logger, utility, newrelic, postman):
		self.name = name
		self.is_ssl = is_ssl
		if self.is_ssl:
			self.warning_connections = int(Config.get('webhitscount', 'ssl_warning_connections'))
			self.alert_level =  int(Config.get('webhitscount', 'ssl_alert_level'))
			self.block_level = int(Config.get('webhitscount', 'ssl_block_level'))
		else:
			self.warning_connections = int(Config.get('webhitscount', 'warning_connections'))
			self.alert_level =  int(Config.get('webhitscount', 'alert_level'))
			self.block_level = int(Config.get('webhitscount', 'block_level'))
		self.max_in_list = int(Config.get('webhitscount', 'max_in_list'))
		self.watchlist_duration = int(Config.get('webhitscount', 'watchlist_duration'))
		self.exception_ips = Config.get('basic', 'exception_ips').split(',')
		self.recipients = Config.get('basic', 'recipients').split(',')
		self.enable_newrelic = int(Config.get('basic', 'enable_newrelic'))
		self.logger = logger
		self.utility = utility
		self.newrelic = newrelic
		self.postman = postman
		self.protocol = 'https' if is_ssl else 'http'
		self._queue = {}
		self.watchlist = {}

	@property
	def queue(self):
		return self._queue

	@queue.setter 
	def queue(self, value):
		self._queue = value

	# def isQueueHasKey(self, host):
	# 	return self._queue.has_key(host)

	# def getQueueByHost(self, host):
	# 	return self._queue[host]

	# def setQueueByHost(self, host, raw_json):
	# 	self._queue[host] = raw_json

class WebHitsCount(Rule):	
	def checkWatchlist(self):
		nts = int(time.time())
		hosts = self.watchlist.keys()
		for host in hosts:
			message = ''
			if self.watchlist[host]['in_list'] >= self.max_in_list:
				self.watchlist[host]['in_list'] = 0
				self.watchlist[host]['ts'] = nts
				location = self.utility.getLocation(host)
				now = datetime.datetime.fromtimestamp(nts)
				now = (now.replace(tzinfo=tzlocal())).isoformat(' ')
				count = self.watchlist[host]['count']
				records = json.loads(self.watchlist[host]['raw_json'])
				watchDuration = nts - self.watchlist[host]['sts']

				# When count is over warning_connections * alert_level, an email will be sent out.
				if count >= (self.warning_connections * self.alert_level):
					message = '%s %s(%s, %s, %s) hits %s times in %s seconds.\n' % \
						(now, host, location['cityName'], location['regionName'], location['countryName'], count, watchDuration)
					self.logger.warning(message)

				# When count is over warning_connections * block_level, the host will be blocked.
				if count >= (self.warning_connections * self.block_level):
					self.utility.blockHost(host)
					block_message = '%s is blocked!!' % host
					self.logger.warning(block_message)
					message = '<p>%s</p><p>%s</p>' % (message, block_message)

				if message != '':
					if self.is_ssl:
						subject = 'WARNING!!! Gatekeeper Alert for %s(SSL) from %s' % (self.name, host)
					else:
						subject = 'WARNING!!! Gatekeeper Alert for %s from %s' % (self.name, host)
					#recipients = Config.get('basic', 'recipients').split(',')
					self.postman.sendEmail(message, subject, self.recipients, records)

			# If the host at watchlist is over the watchlist_duration without reaching the warning_connections,
			# the host will be removed from watchlist.		
			if (nts - self.watchlist[host]['ts']) >= self.watchlist_duration:
				del self.watchlist[host]

	def addToWatchlist(self, host, record):
		count = len(json.loads(record))

		if self.watchlist.has_key(host):
			blackrecord = self.watchlist[host]
			blackrecord['count'] = blackrecord['count'] + count
			
			if count >= self.warning_connections:
				blackrecord['in_list'] = blackrecord['in_list'] + 1

			raw_json = json.loads(blackrecord['raw_json'])
			for line in json.loads(self._queue[host]):
				raw_json.append(line)
			raw_json = json.dumps(raw_json)
			blackrecord['raw_json'] = raw_json
			self.watchlist[host] = blackrecord
		else:
			nts = int(time.time())
			blackrecord = {}
			blackrecord['ts'] = nts
			blackrecord['sts'] = nts
			blackrecord['count'] = count
			blackrecord['in_list'] = 1
			blackrecord['raw_json'] = self._queue[host]
			self.watchlist[host] = blackrecord

	def investigate(self, ts):
		inWatchlist = []  # Use to check the keys of metrics whether its host is at watchlist.
		#reqs = [] # Deprecation line 115
		metrics = {}
		hosts = self._queue.keys()
		for host in hosts:
			count = len(json.loads(self._queue[host]))
			message = '%s %s %s' % (ts, host, count)				
			if count >= self.warning_connections and host not in self.exception_ips:
				self.addToWatchlist(host, self._queue[host])
				self.logger.warning(message)
			elif host in self.watchlist.keys():
				self.addToWatchlist(host, self._queue[host])
				self.logger.info(message)
			else:
				self.logger.info(message)

			key = 'Component/Host/Hit Count/%s/%s[hits]' % (self.protocol, host)
			metrics[key] = count

			# If the host is at watchlist, the value will be sent to new relic even under 60 hits.
			if host in self.watchlist.keys():
				inWatchlist.append(key)
			del self._queue[host]

		self.checkWatchlist()

		if len(metrics) > 0 and self.enable_newrelic:
			appTotalHits = self.newrelic.getMetricsValues(metrics.values())

			# Only collect metrics with the values over 60 hits or the hosts at watchlist. 
			metrics = dict((key,value) for key, value in metrics.iteritems() if value > 60 or key in inWatchlist)
			key = 'Component/WebApp/Hit Count/%s[hits]' % self.protocol
			
			metrics[key] = appTotalHits
			self.newrelic.sendMetrics(metrics)