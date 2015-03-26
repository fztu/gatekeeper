#!/usr/bin/python
import psutil
import smtplib 
import os 
import commands
import MySQLdb
import re
import threading
import time

class SystemMonitor(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.server = 'ee14.silksoftware.net'
		self.webProcess = 'httpd'
		self.db_host = 'localhost'
		self.username = 'root'
		self.password = '12345abc'
		self.database = 'ee14'

	def connectDB(self):
		self.db = MySQLdb.connect(self.db_host, self.username, self.password, self.database)

	def closeDB(self):
		self.db.close()		

	def insertEntity(self, sql):
		cursor = self.db.cursor()
		try:
			cursor.execute(sql)
			self.db.commit()
			return cursor.lastrowid
		except:
			self.db.rollback()

	def getWebProcessCount(self):
		totalHttpd = 0
		for proc in psutil.process_iter():
			try:
				pinfo = proc.as_dict(attrs=['pid', 'name'])
			except psutil.NoSuchProcess:
				pass
			else:
				if pinfo['name'] == self.webProcess:
					totalHttpd = totalHttpd + 1
		return totalHttpd

	def getCpuPercent(self):
		cpu_percent_list = []
		for i in range(0, 5):
			cpu_percent_list.append(psutil.cpu_percent(interval=1.0))
			time.sleep(2.00)

		sorted(cpu_percent_list)
		cpu_percent = cpu_percent_list[-1]

		return cpu_percent

	def insertSystemData(self, cpu_percent, web_process_count):
		vmem = psutil.virtual_memory()
		swap = psutil.swap_memory()
		disk = psutil.disk_usage('/')
		
		self.connectDB()
		sql = """
			insert into gk_system_monitor (server, cpu_percent, web_process_count, vmem_total, vmem_available, vmem_percent, vmem_used, vmem_free,
			vmem_active, vmem_inactive, vmem_buffers, vmem_cached, swap_total, swap_used, swap_free, swap_percent, swap_sin, swap_sout,
			disk_total, disk_used, disk_free, disk_percent, created_at)
			values ('%s', %.2f, %d, %d, %d, %.2f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %.2f, %d, %d, %d, %d, %d, %.2f, now());""" \
			% (self.server, cpu_percent, web_process_count, vmem.total, vmem.available, vmem.percent, vmem.used, vmem.free, \
				vmem.active, vmem.inactive, vmem.buffers, vmem.cached, swap.total, swap.used, swap.free, swap.percent, swap.sin, swap.sout, \
				disk.total, disk.used, disk.free, disk.percent) 
		id = self.insertEntity(sql)
		self.closeDB()
		return id

	def getNetData(self):
		keys = ['Proto', 'Recv-Q', 'Send-Q', 'Local Address', 'Foreign Address', 'State']
		ns = commands.getoutput("netstat -tn | grep ':80 \|:443'")

		lines = ns.split('\n')

		webConnections = {}
		for line in lines:
			netstat = {}
			cols = line.split()

			for i in range(0, len(cols)):
				netstat[keys[i]] = cols[i]

			if netstat.has_key('Foreign Address'):
				foreign_address = netstat['Foreign Address'].split(':')
				if len(foreign_address) == 2:
					netstat['Foreign Address'] = foreign_address[0]
				else:
					netstat['Foreign Address'] = foreign_address[3]

				ip = netstat['Foreign Address']
				if webConnections.has_key(ip):
					webConnections[ip] = webConnections[ip] + 1
				else:
					webConnections[ip] = 1

		return webConnections

	def insertNetData(self, parent_id, webConnections):
		self.connectDB()
		for ip, total_con in webConnections.items():
			sql = """insert into gk_system_monitor_netstat (foreign_address, total_con, parent_id, created_at)
					values ('%s', %s, %s, now());""" % (ip, total_con, parent_id)
			self.insertEntity(sql)
		self.closeDB()

	def insertNetLog(self, netLogs):
		self.connectDB()
		for ip, netLog in netLogs.items():
			sql = """insert into gk_net_log (foreign_address, city, region, country, agent, measure, level, total_amt, created_at)
					values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, now());""" \
					% (ip, netLog['city'], netLog['region'], netLog['country'], netLog['agent'], netLog['measure'], netLog['level'], netLog['total_amt'])
			self.insertEntity(sql)
		self.closeDB()

	def run(self):
		timeSlot = int(time.time())
		while True:
			if int(time.time()) - timeSlot >= 60:
				cpu_percent = self.getCpuPercent()
				web_process_count = self.getWebProcessCount()

				print cpu_percent, web_process_count

				parent_id = self.insertSystemData(cpu_percent, web_process_count)
				webConnections = self.getNetData()
				self.insertNetData(parent_id, webConnections)
				timeSlot = int(time.time())


if __name__ == '__main__':
	systemMonitor = SystemMonitor()
	systemMonitor.setDaemon(True)
	systemMonitor.start()
	systemMonitor.join()
