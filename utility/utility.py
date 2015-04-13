#!/user/bin/python
import logging
import logging.handlers
import csv
import requests
import os
import time
import json
import socket
import requests
import smtplib
import ConfigParser
import StringIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
import pyipinfodb

Config = ConfigParser.ConfigParser()
Config.read("/opt/gatekeeper/gatekeeper.cfg")

# NewRelic Setting.
__version__ = Config.get('basic', 'version')
guid = 'com.silksoftware.plugin.gatekeeper'
newrelic_endpoint = 'https://platform-api.newrelic.com/platform/v1/metrics'
newrelic_license_key = Config.get('basic', 'newrelic_license_key')

# IPInfoDB Setting.
ipinfodb_key = Config.get('basic', 'ipinfodb_key')

# PostMan Setting.
sender = Config.get('basic', 'sender')
remote_smtpserver = int(Config.get('basic', 'remote_smtpserver'))
server = Config.get('smtpserver', 'server')
port = Config.get('smtpserver', 'port')
username = Config.get('smtpserver', 'username')
password = Config.get('smtpserver', 'password')

class Logger():
	def __init__(self, appname, is_ssl):
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

	def error(self, message):
		self.logger.error(message)

	def debug(self, message):
		self.logger.debug(message)

	def warning(self, message):
		self.logger.warning(message)

	def info(self, message):
		self.logger.info(message)


class Utility():
	def __init__(self, logger):
		self.ip_info = pyipinfodb.IPInfo(ipinfodb_key)
		self.logger = logger

	def isJson(self, line):
		try:
			json_object = json.loads(line)
		except ValueError, e:
			return False
		return True

	def getLocation(self, host):
		try:
			time.sleep(2.00)
			location = self.ip_info.get_city(host)
			return location
		except Exception as inst:
			self.logger.error(type(inst))
			self.logger.error(inst.args)

	def blockHost(self, host):
		blockInput = 'iptables -A INPUT -s %s/32 -j DROP' % host
		blockOutput = 'iptables -A OUTPUT -d %s/32 -j DROP' % host
		os.system(blockInput)
		os.system(blockOutput)	


class NewRelic():
	def __init__(self, appname, logger):
		self.agent_data = {'host': socket.gethostname(),
							'pid': os.getpid(),
							'version': __version__}
		self.http_headers = {'Accept': 'application/json',
							'Content-Type': 'application/json',
							'X-License-Key': newrelic_license_key}
		self.endpoint = newrelic_endpoint
		self.name = appname
		self.guid = guid
		self.logger = logger

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
			response = requests.post(self.endpoint,
									headers=self.http_headers,
									data=json.dumps(body, ensure_ascii=False),
									timeout=10,
									verify=True)
			self.logger.debug('Response: %s: %r', response.status_code, response.content.strip())
		except requests.ConnectionError as error:
			self.logger.error('Error reporting stats: %s', error)
		except requests.Timeout as error:
			self.logger.error('TimeoutError reporting stats: %s', error)


class PostMan():
	def __init__(self):
		self.sender = sender
		self.remote_smtpserver = remote_smtpserver
		self.server = server
		self.port = port
		self.username = username
		self.password = password
	
	def initMailServer(self):
		if self.remote_smtpserver:
			self.smtpserver = smtplib.SMTP(self.server, self.port)
			self.smtpserver.ehlo()
			self.smtpserver.starttls()
			self.smtpserver.ehlo()
			self.smtpserver.login(self.username, self.password)
		else:
			self.smtpserver = smtplib.SMTP('localhost')

	def sendEmail(self, message, subject, recipients, records=None):
		self.initMailServer()
		msg = self.getMailContent(subject, recipients, message, records)
		self.smtpserver.sendmail(self.sender, recipients, msg.as_string())
		self.smtpserver.close()

	def getMailContent(self, subject, recipients, message, records):
		outer = MIMEMultipart()
		outer['Subject'] = subject 
		outer['From'] = self.sender
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

		if records is not None:
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

	