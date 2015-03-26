
select
t0.cpu_percent,
t0.httpd_count,
t1.created_at,
t1.foreign_address,
count(t1.foreign_address) as amt 
from 
load_detect t0,
load_detect_netstat t1
where t0.id = t1.load_detect_id
and (t0.cpu_percent >= 80 or t0.httpd_count >= 150)
and t1.created_at >= '2015-02-22' 
and t1.created_at < '2015-02-23' 
group by
t0.cpu_percent,
t0.httpd_count,
t1.created_at, 
t1.foreign_address 
having amt > 100;



select
foreign_address,
count(*) as amt
from load_detect_netstat
where created_at >= '2015-02-22' 
and created_at < '2015-02-23' 
group by foreign_address
order by amt desc
limit 10;
