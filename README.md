Gatekeeper
==========

## Synopsis

**Gatekeeper** is developed to analyze the log of the web server (Apache, Nginx) to identify the suspective internet traffic in real time which might be the source of the DDOS attack.  **Gatekeeper** also integrates with **New Relic** for monitoring.  The statistic data will be collected and aggregated minus by minus and transferred to **New Relic** per minus.  If the identified traffic reaches the warning level of a rule setting, a warning email will be broadcasted out.  When the traffic hits the **block** condition of a rule, **gatekeeper** would block the suspective source by **iptables** and broadcasts out an email. 

## Requirement

The required python packages need to be installed.

* pyipinfodb(https://github.com/mossberg/pyipinfodb)

	python-pip install git+git://github.com/markmossberg/pyipinfodb.git
