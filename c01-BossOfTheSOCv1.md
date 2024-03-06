# Boss Of The SOC v1
Type: Incident response


### Scenario 1 - Web

Q2: What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?
40.80.148.42

sourcetype=suricata imreallynotbatman.com src_ip="40.80.148.42"

Q3: What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

surricata signature field contains tool identification -> acunetix

Q4: What content management system is imreallynotbatman.com likely using?
Look at successfull GET requests -> http.status = 200
index="botsv1" sourcetype=suricata imreallynotbatman.com src_ip="40.80.148.42" http.status=200
Urls mit joomla -> joomla

Q5: What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?
We have to look at Logs of Webserver -> IP of webserver is 192.168.250.70 
enter IP in search bar -> host 
data contains http stream of hosts -> c_ip (client ip)
index="botsv1" c_ip="192.168.250.70" -> gives all http traffic from web server, here we can see all requests performed by the server
in this case, a image was loaded from http://prankglassinebracket.jumpingcrab.com:1337:1337/poisonivy-is-coming-for-you-batman.jpeg

Q6: This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
see above, prankglassinebracket.jumpingcrab.com

Q7: What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?
see also above, the IP that prankglassinebracket.jumpingcrab.com resolved to, i.e. the dest_ip of the request for the image
23.22.63.114

Q8: What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?
Search for all incoming requests to the website:
e.g. source="stream:http" site=imreallynotbatman.com or source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70"

look at requests, usefull to aggregate by source IP and e.g. http status code

index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST | stats count BY src, status

Q9: What is the name of the executable uploaded by Po1s0n1vy? 

search for http post traffic with large in_byte value, search for file, multipart/form-data,
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST bytes_in >= 1000 "multipart/form-data"
answer is in field part_filename{}

Q10: What is the MD5 hash of the executable uploaded?

in Windows Operational Logs
index="botsv1" 3791.exe source="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="3791.exe"

Q11: GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

Search for initial IP (23.22.63.114) on VT
https://www.virustotal.com/gui/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8

Q12: What special hex code is associated with the customized malware discussed in question 111?
VT -> community tab comment

Q13: What was the first brute force password used?
same query as before, get brute force source ip using 
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST | stats count BY src, status
after getting the ip, display time and form_data
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  src="23.22.63.114" | table _time, form_data | sort by _time asc

Q14: One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

Extract password field using regular expression
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  src="23.22.63.114" | table _time, form_data | rex field=form_data "passwd=(?<passwd>[^&]+)"  | where len(passwd) = 6

then export and search or something

Q15: What was the correct password for admin access to the content management system running "imreallynotbatman.com"?
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  uri="/joomla/administrator/index.php" | table  _time, src_ip, status, form_data  | rex  field=form_data "passwd=(?<passwd>[^&]+)"

Q16: What was the average password length used in the password brute forcing attempt?
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  uri="/joomla/administrator/index.php"  src_ip="23.22.63.114" | table  _time, src_ip, status, form_data   | rex  field=form_data "passwd=(?<passwd>[^&]+)" | eval l=len(passwd) | stats avg(l) by src_ip

Q17: How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? 

index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  uri="/joomla/administrator/index.php" | table _time, src_ip, status, form_data   | rex field=form_data "passwd=(?<passwd>[^&]+)" | search passwd=batman



successfull bruteforce from attacker: 21:46:33.689

hands on logon from attacker 21:48:05.858

using transaction <field> groups by same field and displays the duration > 92.169084
index="botsv1" source="stream:http" imreallynotbatman.com dest_ip="192.168.250.70" http_method=POST  uri="/joomla/administrator/index.php"  | table  _time, src_ip, status, form_data   | rex field=form_data "passwd=(?<passwd>[^&]+)" | search passwd=batman | transaction passwd

Q18: How many unique passwords were attempted in the brute force attempt?


### Scenario 2 - APT

Q1: What was the most likely IPv4 address of we8105desk on 24AUG2016
index="botsv1" we8105desk src_host="we8105desk.waynecorpinc.local" -> src IP is 192.168.250.100


Q2: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.
index="botsv1" source="/var/log/suricata/eve.json" Cerber -> look at signature -> signature="ETPRO TROJAN Ransomware/Cerber Checkin 2"

Q3: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?
