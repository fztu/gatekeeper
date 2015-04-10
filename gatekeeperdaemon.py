#!/user/bin/python
import sys
import syslog 
import os
import traceback
import time 
import datetime
import json
import ConfigParser
import threading
from dateutil.tz import tzlocal
from daemon import Daemon
from time import sleep
from sh import tail
import csv
import utility

Config = ConfigParser.ConfigParser()
Config.read("/opt/gatekeeper/gatekeeper.cfg")
module = __import__("rule.rule")
rules = Config.get('basic', 'rules').split(',')

theLock = threading.Lock()

def synchronized(lock):
	'''Synchronization decorator.'''
	def wrap(f):
		def newFunction(*args, **kw):
			lock.acquire()
			try:
				return f(*args, **kw)
			finally:
				lock.release()
		return newFunction
	return wrap

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
	def __init__(self, appname, access_log, is_ssl=0):
		threading.Thread.__init__(self)
		self.is_ssl = is_ssl
		self.access_log = access_log

		self.logger = utility.Logger(appname, is_ssl)
		self.utility = utility.Utility(self.logger)
		self.newrelic = utility.NewRelic(appname, self.logger)
		self.postman = utility.PostMan()

		self.rules = {}
		for rule in rules:
			ruleClass = getattr(module, rule)
			self.rules[rule] = ruleClass(appname, is_ssl, self.logger, self.utility, self.newrelic, self.postman)

	def addToQueue(self, res):
		for k, v in self.rules.items():
			if v.queue.has_key(res["host"]):
				raw_json = v.queue[res["host"]]
				records = json.loads(raw_json)
				records.append(res)
				raw_json = json.dumps(records)
				v.queue[res["host"]] = raw_json
			else:
				records = []
				records.append(res)
				raw_json = json.dumps(records)
				v.queue[res["host"]] = raw_json

	def investigate(self, ts):
		for k, v in self.rules.items():
			v.investigate(ts)

	def run(self):
		# checkThread = False  ## Ping the webApp
		threadLife = 1800
		try:
			timeSlot = int(time.time())
			n = datetime.datetime.now()
			dt = datetime.datetime(n.year, n.month, n.day, n.hour, n.minute, 0, tzinfo=tzlocal())
			ts = dt.isoformat(' ')
			for line in tail("-f", self.access_log, _iter=True):
				if int(time.time()) - timeSlot >= 60:
					self.investigate(ts)
					timeSlot = int(time.time())
					n = datetime.datetime.now()
					dt = datetime.datetime(n.year, n.month, n.day, n.hour, n.minute, 0, tzinfo=tzlocal())
					ts = dt.isoformat(' ')

				if self.utility.isJson(line):
					# checkThread = False  ## Ping the webApp
					threadLife = 1800
					res = json.loads(line)
					res["query"] = None if res["query"] == '' else res["query"]
					res["status"] = int(res["status"])
					res["size"] = 0	if res["size"] == "-" else int(res["size"])
					res["referer"] = None if res["referer"] == "-" else res["referer"]
					res["responseTime"] = int(res["responseTime"])

					self.addToQueue(res)

				else:
					if threadLife == 0:
						if not self.is_ssl:
							syslog.syslog('%s gatekeeper thread restarting...' % self.name)
						else:
							syslog.syslog('%s ssl gatekeeper thread restarting...' % self.name)
						break
					else:
						threadLife = threadLife - 30
						time.sleep(30)
						continue

		except IOError:
			syslog.syslog('Error(%s): can\'t find file (%s) or read data.' % (self.name, self.access_log))

		if threadLife == 0:
			self.run()

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
			appnames = Config.options('appnames')
			for appname in appnames:
				enable = int(Config.get('appnames', appname))
				if enable:
					access_log = Config.get(appname, 'access_log')
					if access_log != '':
						gatekeeper = Gatekeeper(appname, access_log)
						gatekeeper.start()
						syslog.syslog('%s gatekeeper thread starting...' % appname)
					else:
						syslog.syslog('Please specify the access_log for %s.' % appname)
					time.sleep(1)

					ssl_access_log = Config.get(appname, 'ssl_access_log')
					if ssl_access_log != '':
						sslgatekeeper = Gatekeeper(appname, ssl_access_log, 1)
						sslgatekeeper.start()
						syslog.syslog('%s ssl gatekeeper thread starting...' % appname)
					else:
						syslog.syslog('Please specify the ssl_access_log for %s.' % appname)
					time.sleep(1)

		except Exception, e:
			self.formatExceptionInfo()


