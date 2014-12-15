#!/user/bin/python
import sys
import syslog 
import os
import traceback
import time 
import datetime
import json 
import re 
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

Config = ConfigParser.ConfigParser()
Config.read("/opt/gatekeeper/gatekeeper.cfg")

__version__ = Config.get('basic', 'version')
guid = 'com.silksoftware.plugin.gatekeeper'
newrelic_endpoint = 'https://platform-api.newrelic.com/platform/v1/metrics'
license_key = Config.get('basic', 'license_key')
enable_newrelic = int(Config.get('basic', 'enable_newrelic'))
ipinfodb_key = Config.get('basic', 'ipinfodb_key')
ip_info = pyipinfodb.IPInfo(ipinfodb_key)

warning_connection_level = int(Config.get('basic', 'warning_connection_level'))
ssl_warning_connection_level = int(Config.get('basic', 'ssl_warning_connection_level'))
max_in_list = int(Config.get('basic', 'max_in_list'))
watchlist_duration = int(Config.get('basic', 'watchlist_duration'))
exception_ips = (Config.get('basic', 'exception_ips')).split(',')
parts = (Config.get('basic', 'parts')).split(',')
ssl_parts = (Config.get('basic', 'ssl_parts')).split(',')


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
	def __init__(self, access_log, appname, warning_connection_level, is_ssl=0):
		threading.Thread.__init__(self)
		self.queue = {}
		self.watchlist = {}
		self.is_ssl = is_ssl
		self.pattern = re.compile(r'\s+'.join(ssl_parts)+r'\s*\Z') if self.is_ssl \
			else re.compile(r'\s+'.join(parts)+r'\s*\Z')
		
		self.access_log = access_log
		self.warning_connection_level = warning_connection_level

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
		self.agent_data = {'host': socket.gethostname(),
							'pid': os.getpid(),
							'version': __version__}
		self.http_headers = {'Accept': 'application/json',
							'Content-Type': 'application/json',
							'X-License-Key': license_key}
		self.endpint = newrelic_endpoint
		self.name = appname
		self.guid = guid
		self.enable_newrelic = enable_newrelic
		self.protocol = 'https' if is_ssl else 'http'
		self.max_in_list = max_in_list
		self.watchlist_duration = watchlist_duration
		self.exception_ips = exception_ips

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

	def getReqMetrics(self, reqs):
		reqDict = {}
		for req in reqs:
			req_str = (req['request']).split(' ')
			method = req_str[0]
			req_url = req_str[1].replace('/', '\\')
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

				message = '%s %s(%s, %s, %s) hits %s times in %s seconds.\n' % \
					(now, host, location['cityName'], location['regionName'], location['countryName'], count, self.watchlist_duration)
				self.logger.warning(message)

				self.sendEmail(message, records, host)
			if (nts - self.watchlist[host]['ts']) >= self.watchlist_duration:
				del self.watchlist[host]

	def addToWatchlist(self, host, record):
		if self.watchlist.has_key(host):
			blackrecord = self.watchlist[host]
			blackrecord['count'] = blackrecord['count'] + record['count']
			
			if record['count'] >= self.warning_connection_level:
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
				csvwriter.writerow(records[i].keys()) 
			csvwriter.writerow(records[i].values())
		
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

	def investigate(self, ts):
		self.checkWatchlist()

		inWatchlist = []  # Use to check the keys of metrics whether its host is at watchlist.
		reqs = []
		metrics = {}
		hosts = self.queue.keys()
		for host in hosts:
			tszs = self.queue[host].keys()
			for tsz in tszs:
				if tsz != ts:

					for line in json.loads(self.queue[host][tsz]["raw_json"]):
						reqs.append(line)

					count = self.queue[host][tsz]["count"]
					message = '%s %s %s' % (tsz, host, count)				
					if count >= self.warning_connection_level and host not in self.exception_ips:
						self.addToWatchlist(host, self.queue[host][tsz])
						self.logger.warning(message)
					elif host in self.watchlist.keys():
						self.addToWatchlist(host, self.queue[host][tsz])
						self.logger.info(message)
					else:
						self.logger.info(message)

					key = 'Component/Host/Hit Count/%s/%s[hits]' % (self.protocol, host)
					metrics[key] = count

					# If the host is at watchlist, the value will be sent to new relic even under 60 hits.
					if host in self.watchlist.keys():
						inWatchlist.append(key)

					del self.queue[host][tsz]

			if len(self.queue[host]) == 0:
				del self.queue[host]
		if len(metrics) > 0 and self.enable_newrelic:
			appTotalHits = self.getMetricsValues(metrics.values())

			# Only collect metrics with the values over 60 hits or the hosts at watchlist. 
			metrics = dict((key,value) for key, value in metrics.iteritems() if value > 60 or key in inWatchlist)
			key = 'Component/WebApp/Hit Count/%s[hits]' % self.protocol
			
			metrics[key] = appTotalHits
			reqMetrics = self.getReqMetrics(reqs)
			self.sendMetrics(dict(metrics, **reqMetrics))
	
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
						timeSlot = int(time.time())
						n = datetime.datetime.now()
						dt = datetime.datetime(n.year, n.month, n.day, n.hour, n.minute, 0, tzinfo=tzlocal())
						ts = dt.isoformat(' ')

					self.investigate(ts)
					line = log.readline()
					m = self.pattern.match(line)
					if m is not None:
						res = m.groupdict()
						#print res
						res["user"] = None if res["user"] == "-" else res["user"]

						res["status"] = int(res["status"])

						res["size"] = 0	if res["size"] == "-" else int(res["size"])
						
						if res.has_key("referer"):
							res["referer"] = None if res["referer"] == "-" else res["referer"]

						if self.queue.has_key(res["host"]):
							if self.queue[res["host"]].has_key(ts):
								record = self.queue[res["host"]][ts]
								record['count'] = record['count'] + 1
								raw_json = json.loads(record['raw_json'])
								raw_json.append(res)
								raw_json = json.dumps(raw_json)
								record['raw_json'] = raw_json
								self.queue[res["host"]][ts] = record
							else:
								record = {}
								record['count'] = 1
								raw_json = []
								raw_json.append(res)
								raw_json = json.dumps(raw_json)
								record['raw_json'] = raw_json
								self.queue[res["host"]][ts] = {}
								self.queue[res["host"]][ts] = record
						else:
							record = {}
							record['count'] = 1
							raw_json = []
							raw_json.append(res)
							raw_json = json.dumps(raw_json)
							record['raw_json'] = raw_json
							self.queue[res["host"]] = {}
							self.queue[res["host"]][ts] = {}
							self.queue[res["host"]][ts] = record

					else:
						time.sleep(30)          # avoid busy waiting
	            		# f.seek(0, io.SEEK_CUR) # appears to be unneccessary
						if os.path.exists(self.access_log):
							continue
						else:
							self.kill()

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
						gatekeeper = Gatekeeper(access_log, appname, warning_connection_level)
						gatekeeper.start()
						syslog.syslog('%s gatekeeper thread starting...' % appname)
						t['access_log'] = access_log
						t['gatekeeper'] = gatekeeper
					else:
						syslog.syslog('Please specify the access_log for %s.' % appname)

					ssl_access_log = Config.get(appname, 'ssl_access_log')
					if ssl_access_log != '':
						sslgatekeeper = Gatekeeper(ssl_access_log, appname, ssl_warning_connection_level, 1)
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
							gatekeeper = Gatekeeper(v['access_log'], k, warning_connection_level)
							gatekeeper.start()
							syslog.syslog('%s gatekeeper thread starting...' % k)
							threadSet[k]['gatekeeper'] = gatekeeper
					if v.has_key('sslgatekeeper') and not v['sslgatekeeper'].isAlive():
						syslog.syslog('%s ssl gatekeeper is not alive...' % k)
						if os.path.exists(v['ssl_access_log']):
							sslgatekeeper = Gatekeeper(v['ssl_access_log'], k, ssl_warning_connection_level, 1)
							sslgatekeeper.start()
							syslog.syslog('%s ssl gatekeeper thread starting...' % k)
							threadSet[k]['sslgatekeeper'] = sslgatekeeper

		except Exception, e:
			self.formatExceptionInfo()


