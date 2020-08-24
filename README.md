# Deep Security Reports

Creates reports on your Deep Security protected hosts and the virtual patches which are applied to them.

## Setup Instructions

1. Download & install the [Deep Security SDK](https://automation.deepsecurity.trendmicro.com/article/12_5/python?platform=dsaas).
2. Create Deep Security [API keys](https://automation.deepsecurity.trendmicro.com/article/11_1/create-and-manage-api-keys?platform=dsaas#create-an-api-key-in-deep-security-manager).
3. Set the API key as a `DS_KEY` environment variable.

## Usage Instructions
### Help Menu

```
$ python3 reporter.py -h
usage: reporter.py [-h] [--report-filename REPORT_FILENAME]
                   [--summary-filename SUMMARY_FILENAME]
                   [--app-names [APP_NAMES [APP_NAMES ...]]] --dsm-address
                   DSM_ADDRESS

Deep Security IPS Report

optional arguments:
  -h, --help                               show this help message and exit
  --report-filename REPORT_FILENAME        IPS report filename (default: ips_report.csv
  --summary-filename SUMMARY_FILENAME      IPS summary filename (default: ips_summary.csv
  --app-names [APP_NAMES [APP_NAMES ...]]  App names to search for in the IPS report

required arguments:
  --dsm-address DSM_ADDRESS                e.g https://app.deepsecurity.trendmicro.com/api
```

## Example Usage

```
python3 reporter.py --dsm-address https://app.deepsecurity.trendmicro.com/api --app-names 'Apache Struts' 'NGINX' 'Internet Explorer'
```

Specifying `--app-names` results in an "App Name" column being added to the report CSV file. This enables users to easily group and identify vulnerable applications.

Note that the search is case insensitive. Therefore, in the above example, 'nginx', 'Nginx' and 'NGINX' would all be found.  

## Example Outputs
### Report

```
Hostname,Display Name,Host Description,Platform,Last IP Used,Agent Version,Policy ID,Last Agent Comms.,IPS Agent State,IPS Status,Rule Name,Rule ID,Rule Description,App Category,App Description,App Port(s),Direction,Protocol,CVE(s),CVE Year,CVSS Score,Severity,Rule Type
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts OGNL Expression Remote Command Execution Vulnerability (CVE-2018-11776),6187,Apache Struts is prone to a remote code-execution vulnerability. Successfully exploiting this issue may allow an attacker to execute arbitrary code in the context of the affected application. Failed exploit attempts may cause a denial-of-service condition.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2018-11776,2018,9.30,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts OGNL Expression Injection Vulnerability,6410,Apache Struts is prone to a security-bypass vulnerability because it fails to adequately handle user-supplied input. Attackers can exploit this issue to manipulate server-side context objects with the privileges of the user running the application. Successful exploits can compromise the application and possibly the underlying computer.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2013-2115,2013,9.30,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts OGNL Expression Injection Vulnerability,6410,Apache Struts is prone to a security-bypass vulnerability because it fails to adequately handle user-supplied input. Attackers can exploit this issue to manipulate server-side context objects with the privileges of the user running the application. Successful exploits can compromise the application and possibly the underlying computer.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2013-4212,2013,9.30,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts OGNL Expression Injection Vulnerability,6410,Apache Struts is prone to a security-bypass vulnerability because it fails to adequately handle user-supplied input. Attackers can exploit this issue to manipulate server-side context objects with the privileges of the user running the application. Successful exploits can compromise the application and possibly the underlying computer.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2013-1966,2013,9.30,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Commons FileUpload DiskFileItem File Manipulation Remote Code Execution Vulnerability (CVE-2016-1000031),6447,Apache Commons FileUpload is prone to a remote code execution vulnerability. Successfully exploiting this issue allows attackers to execute arbitrary code in the context of the affected application.,Java RMI,"Java Remote Method Invocation (Java RMI) is a Java API that performs remote method invocation, the object-oriented equivalent of remote procedure calls (RPC), with support for direct transfer of serialized Java classes and distributed garbage-collection.",1099,incoming,tcp,CVE-2016-1000031,2016,10.00,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Java Unserialize Remote Code Execution Vulnerability,6610,There is an unknown Java unserialization vulnerability in third-party Java libraries that could be used to remotely exploit Java based web applications. Serialization is a process in which an object is converted to a stream of bytes in order to store or transmit that object to memory or a file. The process in which serialized data is extracted is called unserialization and it can lead to major security issues if not handled properly.,Web Server Common,Smart and vulnerability facing filters common to all web servers.,119,incoming,tcp,CVE-2015-7501,2015,10.00,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Java Unserialize Remote Code Execution Vulnerability,6610,There is an unknown Java unserialization vulnerability in third-party Java libraries that could be used to remotely exploit Java based web applications. Serialization is a process in which an object is converted to a stream of bytes in order to store or transmit that object to memory or a file. The process in which serialized data is extracted is called unserialization and it can lead to major security issues if not handled properly.,Web Server Common,Smart and vulnerability facing filters common to all web servers.,119,incoming,tcp,CVE-2015-4852,2015,10.00,critical,exploit
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Java Unserialize Remote Code Execution Vulnerability,6610,There is an unknown Java unserialization vulnerability in third-party Java libraries that could be used to remotely exploit Java based web applications. Serialization is a process in which an object is converted to a stream of bytes in order to store or transmit that object to memory or a file. The process in which serialized data is extracted is called unserialization and it can lead to major security issues if not handled properly.,Web Server Common,Smart and vulnerability facing filters common to all web servers.,119,incoming,tcp,CVE-2015-7450,2015,10.00,critical,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Microsoft MFC Insecure Library Loading Vulnerability Over Network Share (CVE-2010-3190),6378,A remote code execution vulnerability exists in the way that certain applications built using Microsoft Foundation Classes (MFC) handle the loading of DLL files. An attacker who successfully exploited this vulnerability could take complete control of an affected system.,DCERPC Services - Client,,"139, 445",outgoing,tcp,CVE-2010-3190,2010,9.30,critical,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Microsoft MFC Insecure Library Loading Vulnerability Over WebDAV (CVE-2010-3190),6379,A remote code execution vulnerability exists in the way that certain applications built using Microsoft Foundation Classes (MFC) handle the loading of DLL files. An attacker who successfully exploited this vulnerability could take complete control of an affected system.,Web Client Common,,5,outgoing,tcp,CVE-2010-3190,2010,9.30,critical,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Speculative Execution Information Disclosure Vulnerabilities (Spectre),6419,"This DPI rule protects against known public exploits for the information disclosure vulnerability in JavaScript known as Spectre.
The specific vulnerability is due to a flaw in the speculative execution method employed by modern processors. By performing specific actions in JavaScript, an attacker can access all system memory. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

Note: This rule provides protection against recently published remote JavaScript exploits of the vulnerability known as Spectre. It may not provide protection against other remote or local exploitation attempts.",Web Client Common,,5,outgoing,tcp,CVE-2017-5753,2017,4.70,medium,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Speculative Execution Information Disclosure Vulnerabilities (Spectre),6419,"This DPI rule protects against known public exploits for the information disclosure vulnerability in JavaScript known as Spectre.
The specific vulnerability is due to a flaw in the speculative execution method employed by modern processors. By performing specific actions in JavaScript, an attacker can access all system memory. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

Note: This rule provides protection against recently published remote JavaScript exploits of the vulnerability known as Spectre. It may not provide protection against other remote or local exploitation attempts.",Web Client Common,,5,outgoing,tcp,CVE-2017-5715,2017,4.70,medium,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Microsoft Internet Explorer 'Tree::Notify_InvalidateDisplay' Null Pointer Dereference Vulnerability,6425,Microsoft Internet Explorer suffers from a NULL pointer deference vulnerability. Successful exploitation could lead to a denial of service attack. This vulnerability could be used to corrupt memory and execute remote code on the client machine.,Web Client Internet Explorer/Edge,,5,outgoing,tcp,,,7.20,high,exploit
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,166,"25/09/2019, 21:40:11 AEST",inactive,"Off, installed, 22 rules",Microsoft Edge And Internet Explorer Same Origin Policy Bypass Vulnerabilities,6676,"Microsoft Edge and Internet Explorer are vulnerable to the same origin policy bypass vulnerability. Successful exploitation would lead the attacker to steal sensitive information like cookies, login session from sites visited by the victim.",Web Client Internet Explorer/Edge,,5,outgoing,tcp,,,6.80,medium,exploit
```

### Summary

```
Hostname,Platform,Last Agent Comms.,IPS Status,# of IPS Rules
ip-172-31-28-113.ap-southeast-2.compute.internal,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),"15/09/2019, 15:02:22 AEST",active,50
WIN-Q0HITV3HJ6D,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,"25/09/2019, 21:40:11 AEST",inactive,22
EC2AMAZ-ID41RIU,Microsoft Windows Server 2016 (64 bit)  Build 14393,"23/10/2019, 11:46:49 AEDT",active,20
```

# Contact

* Blog: oznetnerd.com
* Email: will@oznetnerd.com