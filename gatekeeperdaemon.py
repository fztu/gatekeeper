#!/user/bin/python
import sys
import syslog 
import os
import traceback
import time 
import datetime
import json
import logging
import logging.handlers
import pyipinfodb
import ConfigParser
import smtplib
import socket
import threading
import requests
from dateutil.tz import tzlocal
from daemon import Daemon
from time import sleep
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import StringIO
import csv
import httplib

Config = ConfigParser.ConfigParser()
Config.read("/opt/gatekeeper/gatekeeper.cfg")

__version__ = Config.get('basic', 'version')

# NewRelic Setting.
guid = 'com.silksoftware.plugin.gatekeeper'
newrelic_endpoint = 'https://platform-api.newrelic.com/platform/v1/metrics'
newrelic_license_key = Config.get('basic', 'newrelic_license_key')
enable_newrelic = int(Config.get('basic', 'enable_newrelic'))

# LogEntries Setting.
logentries_endpoint = 'api.logentries.com'
logentries_account_key = Config.get('basic', 'logentries_account_key')
logentries_host_key = Config.get('basic', 'logentries_host_key')
logentries_log_key = Config.get('basic', 'logentries_log_key')
logentries_ssl_log_key = Config.get('basic', 'logentries_ssl_log_key')
enable_logentries = int(Config.get('basic', 'enable_logentries'))

# IPInfoDB Setting.
ipinfodb_key = Config.get('basic', 'ipinfodb_key')
ip_info = pyipinfodb.IPInfo(ipinfodb_key)

warning_connections = int(Config.get('basic', 'warning_connections'))
ssl_warning_connections = int(Config.get('basic', 'ssl_warning_connections'))
max_in_list = int(Config.get('basic', 'max_in_list'))
watchlist_duration = int(Config.get('basic', 'watchlist_duration'))
alert_level = int(Config.get('basic', 'alert_level'))
ssl_alert_level = int(Config.get('basic', 'ssl_alert_level'))
block_level = int(Config.get('basic', 'block_level'))
ssl_block_level = int(Config.get('basic', 'ssl_block_level'))
block_check_duration = int(Config.get('basic', 'block_check_duration'))

exception_ips = (Config.get('basic', 'exception_ips')).split(',')

class Timezone(datetime.tzinfo):
	def __init__(self, name="+0000"):
		self.name = name
		seconds = int(name[:-2])*3600+int(name[-2:])*60
		self.offset = datetime.timedelta(seconds=seconds)

	def utcoffset(self, dt):
		return self.offset

	def dst(self, dt):
		return datetime.timedelta(0)

	def tzname(self, dt):
		return self.name


class Gatekeeper(threading.Thread):
	def __init__(self, access_log, appname, warning_connections, alert_level, block_level, is_ssl=0):
		threading.Thread.__init__(self)
		self.queue = {}
		self.watchlist = {}
		self.is_ssl = is_ssl
		self.access_log = access_log
		self.warning_connections = warning_connections
		self.alert_level = alert_level
		self.block_level = block_level

		GATEKEEPER_NAME = 'gatekeeper' + '_' + appname + '_' + 'ssl' if is_ssl else 'gatekeeper' + '_' + appname

		LOG_FILENAME = '/var/log/' + GATEKEEPER_NAME + '.log'	
		# Set up a specific logger with our desired output level
		self.logger = logging.getLogger(GATEKEEPER_NAME)
		self.logger.setLevel(logging.DEBUG)
		# Add the log message handler to the logger
		handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=10000000, backupCount=5)
		formatter = logging.Formatter('%(levelname)-8s %(message)s')
		handler.setFormatter(formatter)
		self.logger.addHandler(handler)
		
		# Setup for NewRelic
		self.agent_data = {'host': socket.gethostname(),
							'pid': os.getpid(),
							'version': __version__}
		self.http_headers = {'Accept': 'application/json',
							'Content-Type': 'application/json',
							'X-License-Key': newrelic_license_key}
		self.endpint = newrelic_endpoint
		self.name = appname
		self.guid = guid
		self.enable_newrelic = enable_newrelic
		self.protocol = 'https' if is_ssl else 'http'
		self.max_in_list = max_in_list
		self.watchlist_duration = watchlist_duration
		self.exception_ips = exception_ips

		# Setup for LogEntries
		self.logentries_endpoint = logentries_endpoint
		self.logentries_account_key = logentries_account_key
		self.logentries_host_key = logentries_host_key
		self.logentries_log_key = logentries_ssl_log_key if is_ssl else logentries_log_key
		self.enable_logentries = enable_logentries

	def isJson(self, line):
		try:
			json_object = json.loads(line)
		except ValueError, e:
			return False
		return True

	def blockHost(self, host):
		blockInput = 'iptables -A INPUT -s %s/32 -j DROP' % host
		blockOutput = 'iptables -A OUTPUT -d %s/32 -j DROP' % host
		os.system(blockInput)
		os.system(blockOutput)

	# Deprecation	
	def getReqMetrics(self, reqs):
		reqDict = {}
		for req in reqs:
			method = req['method']
			req_url = req['request']
			host = req['host']
			if reqDict.has_key(method):
				if reqDict[method].has_key(req_url):
					if reqDict[method][req_url].has_key(host):
						reqDict[method][req_url][host] = reqDict[method][req_url][host] + 1
					else:
						reqDict[method][req_url][host] = 1
				else:
					reqDict[method][req_url] = {}
					reqDict[method][req_url][host] = 1
			else:
				reqDict[method] = {}
				reqDict[method][req_url] = {}
				reqDict[method][req_url][host] = 1

		reqMetrics = {}
		methodMetrics = {}		
		for method in reqDict:

			methodReqMetrics = {}
			for req_url in reqDict[method]:
				
				methodReqHostMetrics = {}
				for host in reqDict[method][req_url]:
					key = 'Component/MethodReqHost/Hit Count/%s/%s %s %s[hits]' % \
						(self.protocol, method, req_url, host)
					methodReqHostMetrics[key] = reqDict[method][req_url][host]
					#if methodReqHostMetrics[key] > 60:
					#	reqMetrics[key] = methodReqHostMetrics[key]

				key = 'Component/MethodReq/Hit Count/%s/%s %s[hits]' % \
						(self.protocol, method, req_url)
				methodReqMetrics[key] = self.getMetricsValues(methodReqHostMetrics.values())
				#if methodReqMetrics[key]['max'] > 60:
				#	reqMetrics[key] = methodReqMetrics[key]

			key = 'Component/Method/Hit Count/%s/%s[hits]' % \
					(self.protocol, method)
			methodMetrics[key] = self.getMetricsValues(methodReqMetrics.values())
			reqMetrics[key] = methodMetrics[key]	

		return reqMetrics	

	def getMetricsValues(self, values):
		theValues = []
		for value in values:
			if isinstance(value, dict):
				theValues.append(value['total'])
			else:
				theValues.append(value)

		return {'total': sum(theValues),
				'count': len(theValues),
				'min': min(theValues),
				'max': max(theValues),
				'sum_of_squares': sum([i**2 for i in theValues])}

	def checkWatchlist(self):
		nts = int(time.time())
		hosts = self.watchlist.keys()
		for host in hosts:
			if self.watchlist[host]['in_list'] >= self.max_in_list:
				self.watchlist[host]['in_list'] = 0
				self.watchlist[host]['ts'] = nts
				location = self.getLocation(host)
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
				if count >= (self.warning_connections * self.block_level) and watchDuration <= block_check_duration:
					self.blockHost(host)
					block_message = '%s is blocked!!' % host
					self.logger.warning(block_message)
					message = '<p>%s</p><p>%s</p>' % (message, block_message)

				self.sendEmail(message, records, host)

			# If the host at watchlist is over the watchlist_duration without reaching the warning_connections,
			# the host will be removed from watchlist.		
			if (nts - self.watchlist[host]['ts']) >= self.watchlist_duration:
				del self.watchlist[host]

	def addToWatchlist(self, host, record):
		if self.watchlist.has_key(host):
			blackrecord = self.watchlist[host]
			blackrecord['count'] = blackrecord['count'] + record['count']
			
			if record['count'] >= self.warning_connections:
				blackrecord['in_list'] = blackrecord['in_list'] + 1

			raw_json = json.loads(blackrecord['raw_json'])
			for line in json.loads(record['raw_json']):
				raw_json.append(line)
			raw_json = json.dumps(raw_json)
			blackrecord['raw_json'] = raw_json
			self.watchlist[host] = blackrecord
		else:
			nts = int(time.time())
			blackrecord = {}
			blackrecord['ts'] = nts
			blackrecord['sts'] = nts
			blackrecord['count'] = record['count']
			blackrecord['in_list'] = 1
			blackrecord['raw_json'] = record['raw_json']
			self.watchlist[host] = blackrecord

	def getLocation(self, host):
		try:
			sleep(2.00)
			location = ip_info.get_city(host)
			return location
		except Exception as inst:
			self.logger.error(type(inst))
			self.logger.error(inst.args)

	def sendEmail(self, message, records, host):
		if self.is_ssl:
			subject = 'WARNING!!! Gatekeeper Alert for %s(SSL) from %s' % (self.name, host)
		else:
			subject = 'WARNING!!! Gatekeeper Alert for %s from %s' % (self.name, host)
		
		recipients = Config.get('basic', 'recipients').split(',')
		sender = Config.get('basic', 'sender')

		remote_smtpserver = int(Config.get('basic', 'remote_smtpserver'))
		if remote_smtpserver:
			server = Config.get('smtpserver', 'server')
			port = Config.get('smtpserver', 'port')
			username = Config.get('smtpserver', 'username')
			password = Config.get('smtpserver', 'password')
			smtpserver = smtplib.SMTP(server, port)
			smtpserver.ehlo()
			smtpserver.starttls()
			smtpserver.ehlo()
			smtpserver.login(username, password)
		else:
			smtpserver = smtplib.SMTP('localhost')
		
		msg = self.getMailContent(subject, sender, recipients, message, records)
		smtpserver.sendmail(sender, recipients, msg.as_string())

		smtpserver.close()

	def getMailContent(self, subject, sender, recipients, message, records):
		outer = MIMEMultipart()
		outer['Subject'] = subject 
		outer['From'] = sender
		outer['To'] = ','.join(recipients)

		inner = MIMEMultipart('alternative')
		html = """
		<html>
			<head></head>
			<body>
	        	<p>
			<b> """ + message + """ </b>
	        	</p>
			</body>
		</html>
		"""
		part1 = MIMEText(message, 'plain')
		part2 = MIMEText(html, 'html')
		inner.attach(part1)
		inner.attach(part2)
		outer.attach(inner)

		filename = 'apache-access-log.csv'
		csvfile = StringIO.StringIO()
		
		#Python 2.7 or above
		#csvwriter = csv.DictWriter(csvfile, records[0].keys())
		#csvwriter.writeheader()
		#csvwriter.writerows(records)
		
		#Python 2.6.6
		csvwriter = csv.writer(csvfile)
		for i in range(0, len(records)):
			if i == 0:
				keys = ['webApp', 'time', 'host', 'method', 'request',\
						'query', 'status', 'size', 'referer', 'userAgent', 'responseTime']
				csvwriter.writerow(keys)
			values = [records[i]['webApp'], records[i]['time'], records[i]['host'], records[i]['method'],\
					records[i]['request'], records[i]['query'], records[i]['status'], records[i]['size'],\
					records[i]['referer'], records[i]['userAgent'], records[i]['responseTime']] 
			csvwriter.writerow(values)
		
		csv_part = MIMEText(csvfile.getvalue(), 'csv')
		csv_part.add_header('Content-Disposition', 'attachment', filename=filename), outer.attach(csv_part)
		return outer

	def sendMetrics(self, metrics):
		components = []
		component = {}
		component['name'] = self.name
		component['guid'] = self.guid
		component['duration'] = 60
		component['metrics'] = metrics
		components.append(component)
		body = {'agent': self.agent_data, 'components': components}
		self.logger.debug(json.dumps(body, ensure_ascii=False))
		try:
			response = requests.post(self.endpint,
									headers=self.http_headers,
									data=json.dumps(body, ensure_ascii=False),
									timeout=10,
									verify=True)
			self.logger.debug('Response: %s: %r', response.status_code, response.content.strip())
		except requests.ConnectionError as error:
			self.logger.error('Error reporting stats: %s', error)
		except requests.Timeout as error:
			self.logger.error('TimeoutError reporting stats: %s', error)

	def sendLogEntries(self, reqs):
		addr = '/%s/hosts/%s/%s?realtime=1' % \
			(self.logentries_account_key, self.logentries_host_key, self.logentries_log_key)
		conn = httplib.HTTPConnection(self.logentries_endpoint)
		conn.request('PUT', addr)
		for req in reqs:
			conn.send(json.dumps(req) + '\n')
		conn.close()

	def investigate(self, ts):
		self.checkWatchlist()

		inWatchlist = []  # Use to check the keys of metrics whether its host is at watchlist.
		reqs = []
		metrics = {}
		hosts = self.queue.keys()
		for host in hosts:

			for line in json.loads(self.queue[host]["raw_json"]):
				reqs.append(line)

			count = self.queue[host]["count"]
			message = '%s %s %s' % (ts, host, count)				
			if count >= self.warning_connections and host not in self.exception_ips:
				self.addToWatchlist(host, self.queue[host])
				self.logger.warning(message)
			elif host in self.watchlist.keys():
				self.addToWatchlist(host, self.queue[host])
				self.logger.info(message)
			else:
				self.logger.info(message)

			key = 'Component/Host/Hit Count/%s/%s[hits]' % (self.protocol, host)
			metrics[key] = count

			# If the host is at watchlist, the value will be sent to new relic even under 60 hits.
			if host in self.watchlist.keys():
				inWatchlist.append(key)
			del self.queue[host]

		if len(metrics) > 0 and self.enable_newrelic:
			appTotalHits = self.getMetricsValues(metrics.values())

			# Only collect metrics with the values over 60 hits or the hosts at watchlist. 
			metrics = dict((key,value) for key, value in metrics.iteritems() if value > 60 or key in inWatchlist)
			key = 'Component/WebApp/Hit Count/%s[hits]' % self.protocol
			
			metrics[key] = appTotalHits
			self.sendMetrics(metrics)
			# Deprecation line 115
			#reqMetrics = self.getReqMetrics(reqs)
			#self.sendMetrics(dict(metrics, **reqMetrics))

		if len(reqs) > 0 and self.enable_logentries:
			self.sendLogEntries(reqs)
	
	def run(self):
		try:
			with open(self.access_log, 'rb') as log:
				timeSlot = int(time.time())
				n = datetime.datetime.now()
				dt = datetime.datetime(n.year, n.month, n.day, n.hour, n.minute, 0, tzinfo=tzlocal())
				ts = dt.isoformat(' ')
				log.seek(0, 2)
				while True:
					if int(time.time()) - timeSlot >= 60:
						self.investigate(ts)
						timeSlot = int(time.time())
						n = datetime.datetime.now()
						dt = datetime.datetime(n.year, n.month, n.day, n.hour, n.minute, 0, tzinfo=tzlocal())
						ts = dt.isoformat(' ')

					line = log.readline()
					if self.isJson(line):
						res = json.loads(line)
						res["query"] = None if res["query"] == '' else res["query"]
						res["status"] = int(res["status"])
						res["size"] = 0	if res["size"] == "-" else int(res["size"])
						res["referer"] = None if res["referer"] == "-" else res["referer"]
						res["responseTime"] = int(res["responseTime"])

						if self.queue.has_key(res["host"]):
							record = self.queue[res["host"]]
							record['count'] = record['count'] + 1
							raw_json = json.loads(record['raw_json'])
							raw_json.append(res)
							raw_json = json.dumps(raw_json)
							record['raw_json'] = raw_json
							self.queue[res["host"]] = record
						else:
							record = {}
							record['count'] = 1
							raw_json = []
							raw_json.append(res)
							raw_json = json.dumps(raw_json)
							record['raw_json'] = raw_json
							self.queue[res["host"]] = {}
							self.queue[res["host"]] = record

					else:
						time.sleep(30)          # avoid busy waiting
						continue
						#if os.path.exists(self.access_log):
						#	continue
						#else:
						#	if not self.is_ssl:
						#		syslog.syslog('%s gatekeeper thread exiting...' % self.name)
						#	else:
						#		syslog.syslog('%s ssl gatekeeper thread exiting...' % self.name)
						#	break

		except IOError:
			syslog.syslog('Error(%s): can\'t find file (%s) or read data.' % (self.name, self.access_log))


class GatekeeperDaemon(Daemon):
	def formatExceptionInfo(self, maxTBlevel=5):
		cla, exc, trbk = sys.exc_info()
		excName = cla.__name__
		try:
			excArgs = exc.__dict__["args"]
		except KeyError:
			excArgs = "<no args>"
		excTb = traceback.format_tb(trbk, maxTBlevel)

		syslog.syslog(syslog.LOG_ERR, ('Exception: %s' % excName))

		for excArg in excArgs:
			syslog.syslog(syslog.LOG_ERR, ('Error Message: %s' % excArg))

		for trace in excTb:
			syslog.syslog(syslog.LOG_ERR, trace)

		return (excName, excArgs, excTb)

	def run(self):
		try:
			threadSet = {}
			appnames = Config.options('appnames')
			for appname in appnames:
				enable = int(Config.get('appnames', appname))
				if enable:
					t = {}
					access_log = Config.get(appname, 'access_log')
					if access_log != '':
						gatekeeper = Gatekeeper(access_log, appname, warning_connections, alert_level, block_level)
						gatekeeper.start()
						syslog.syslog('%s gatekeeper thread starting...' % appname)
						t['access_log'] = access_log
						t['gatekeeper'] = gatekeeper
					else:
						syslog.syslog('Please specify the access_log for %s.' % appname)

					ssl_access_log = Config.get(appname, 'ssl_access_log')
					if ssl_access_log != '':
						sslgatekeeper = Gatekeeper(ssl_access_log, appname, ssl_warning_connections, ssl_alert_level, ssl_block_level,1)
						sslgatekeeper.start()
						syslog.syslog('%s ssl gatekeeper thread starting...' % appname)
						t['ssl_access_log'] = ssl_access_log
						t['sslgatekeeper'] = sslgatekeeper
					else:
						syslog.syslog('Please specify the ssl_access_log for %s.' % appname)

					threadSet[appname] = t

			while len(threadSet) > 0:
				time.sleep(1)
				for k, v in threadSet.items():
					if v.has_key('gatekeeper') and not v['gatekeeper'].isAlive():
						syslog.syslog('%s gatekeeper is not alive...' % k)
						if os.path.exists(v['access_log']):
							v['gatekeeper'].join()
							del threadSet[k]['gatekeeper']
							gatekeeper = Gatekeeper(v['access_log'], k, warning_connections, alert_level, block_level)
							gatekeeper.start()
							syslog.syslog('%s gatekeeper thread starting...' % k)
							threadSet[k]['gatekeeper'] = gatekeeper
					if v.has_key('sslgatekeeper') and not v['sslgatekeeper'].isAlive():
						syslog.syslog('%s ssl gatekeeper is not alive...' % k)
						if os.path.exists(v['ssl_access_log']):
							v['sslgatekeeper'].join()
							del threadSet[k]['sslgatekeeper']
							sslgatekeeper = Gatekeeper(v['ssl_access_log'], k, ssl_warning_connections, ssl_alert_level, ssl_block_level, 1)
							sslgatekeeper.start()
							syslog.syslog('%s ssl gatekeeper thread starting...' % k)
							threadSet[k]['sslgatekeeper'] = sslgatekeeper

		except Exception, e:
			self.formatExceptionInfo()


