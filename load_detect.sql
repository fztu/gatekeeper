DROP TABLE IF EXISTS gk_system_monitor;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE gk_system_monitor (
  id int(10) unsigned NOT NULL auto_increment,
  cpu_percent decimal(4,2) unsigned,
  web_process_count int(10) unsigned,
  vmem_total bigint unsigned,
  vmem_available bigint unsigned,
  vmem_percent decimal(4,2) unsigned,
  vmem_used bigint unsigned,
  vmem_free bigint unsigned,
  vmem_active bigint unsigned,
  vmem_inactive bigint unsigned,
  vmem_buffers bigint unsigned,
  vmem_cached bigint unsigned,
  swap_total bigint unsigned,
  swap_used bigint unsigned,
  swap_free bigint unsigned,
  swap_percent decimal(4,2) unsigned,
  swap_sin bigint unsigned,
  swap_sout bigint unsigned,
  disk_total bigint unsigned,
  disk_used bigint unsigned,
  disk_free bigint unsigned,
  disk_percent decimal(4,2) unsigned,
  server varchar(100) default NULL,
  created_at timestamp NULL default NULL COMMENT 'Creation Time',
  PRIMARY KEY  (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS gk_system_monitor_netstat;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE gk_system_monitor_netstat (
  id int(10) unsigned NOT NULL auto_increment,
  foreign_address varchar(20) default NULL,
  total_con int(20) unsigned,
  parent_id int(10) unsigned,
  created_at timestamp NULL default NULL COMMENT 'Creation Time',
  PRIMARY KEY  (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS gk_net_log;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE gk_net_log (
  id int(10) unsigned NOT NULL auto_increment,
  foreign_address varchar(20) default NULL,
  city varchar(100) default NULL,
  region varchar(100) default NULL,
  country varchar(100) default NULL,
  agent varchar(100) default NULL,
  measure varchar(100) default NULL,
  level varchar(100) default NULL,
  total_amt int(20) unsigned,
  created_at timestamp NULL default NULL COMMENT 'Creation Time',
  PRIMARY KEY  (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS gk_web_log;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE gk_web_log (
  id int(10) unsigned NOT NULL auto_increment,
  time timestamp NULL default NULL,
  host varchar(20) default NULL,
  webapp varchar(100) default NULL,
  request varchar(250) default NULL,
  query varchar(250) default NULL,
  method varchar(20) default NULL,
  status int(20) unsigned,
  size int(20) unsigned,
  user_agent varchar(250) default NULL,
  referer varchar(250) default NULL,
  response_time int(20) unsigned,
  PRIMARY KEY  (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

