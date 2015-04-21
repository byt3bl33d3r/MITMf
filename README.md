MITMf V0.9.6
============

Framework for Man-In-The-Middle attacks

Quick tutorials, examples and dev updates at http://sign0f4.blogspot.it

This tool is based on [sergio-proxy](https://github.com/supernothing/sergio-proxy) and is an attempt to revive and update the project.

Contact me at:
- Twitter: @byt3bl33d3r
- IRC on Freenode: #MITMf
- Email: byt3bl33d3r@gmail.com

**Before submitting issues please read the appropriate [section](#submitting-issues).**

(Another) Dependency change!
============================
As of v0.9.6, the fork of the ```python-netfilterqueue``` library is no longer required.

Installation
============
If MITMf is not in your distros repo or you just want the latest version:
- clone this repository 
- run the ```setup.sh``` script
- run the command ```pip install -r requirements.txt``` to install all python dependencies

On Kali Linux, if you get an error while installing the pypcap package or when starting MITMf you see: ```ImportError: no module named pcap``` run ```apt-get install python-pypcap``` to fix it.

Availible plugins
=================
- Responder - LLMNR, NBT-NS and MDNS poisoner
- SSLstrip+ - Partially bypass HSTS
- Spoof - Redirect traffic using ARP Spoofing, ICMP Redirects or DHCP Spoofing and modify DNS queries
- Sniffer - Sniffs for various protocol login and auth attempts
- BeEFAutorun - Autoruns BeEF modules based on clients OS or browser type
- AppCachePoison - Perform app cache poison attacks 
- SessionHijacking - Performs session hijacking attacks, and stores cookies in a firefox profile
- BrowserProfiler - Attempts to enumerate all browser plugins of connected clients
- CacheKill - Kills page caching by modifying headers
- FilePwn - Backdoor executables being sent over http using Backdoor Factory and BDFProxy
- Inject - Inject arbitrary content into HTML content
- JavaPwn - Performs drive-by attacks on clients with out-of-date java browser plugins
- jskeylogger - Injects a javascript keylogger into clients webpages
- Replace - Replace arbitary content in HTML content
- SMBAuth - Evoke SMB challenge-response auth attempts
- Upsidedownternet - Flips images 180 degrees

Changelog
=========

- Addition of [DNSChef](https://github.com/iphelix/dnschef), the framework is now a IPv4/IPv6 (TCP & UDP) DNS server ! Supported queries are: 'A', 'AAAA', 'MX', 'PTR', 'NS', 'CNAME', 'TXT', 'SOA', 'NAPTR', 'SRV', 'DNSKEY' and 'RRSIG'

- Addition of the Sniffer plugin which integrates [Net-Creds](https://github.com/DanMcInerney/net-creds) currently supported protocols are:
  FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc..) and Kerberos

- Integrated [Responder](https://github.com/SpiderLabs/Responder) to poison LLMNR, NBT-NS and MDNS, and act as a WPAD rogue server.

- Integrated [SSLstrip+](https://github.com/LeonardoNve/sslstrip2) by Leonardo Nve to partially bypass HSTS as demonstrated at BlackHat Asia 2014 

- Addition of the SessionHijacking plugin, which uses code from [FireLamb](https://github.com/sensepost/mana/tree/master/firelamb) to store cookies in a Firefox profile 

- Spoof plugin can now exploit the 'ShellShock' bug when DHCP spoofing! 

- Spoof plugin now supports ICMP, ARP and DHCP spoofing

- Usage of third party tools has been completely removed (e.g. ettercap)

- FilePwn plugin re-written to backdoor executables and zip files on the fly by using [the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory) and code from [BDFProxy](https://github.com/secretsquirrel/BDFProxy)

- Added [msfrpc.py](https://github.com/byt3bl33d3r/msfrpc/blob/master/python-msfrpc/msfrpc.py) for interfacing with Metasploits rpc server

- Added [beefapi.py](https://github.com/byt3bl33d3r/beefapi) for interfacing with BeEF's RESTfulAPI

- Addition of the app-cache poisoning attack by [Krzysztof Kotowicz](https://github.com/koto/sslstrip) (blogpost explaining the attack here http://blog.kotowicz.net/2010/12/squid-imposter-phishing-websites.html)

Submitting Issues
=================
If you have *questions* regarding the framework please email me at byt3bl33d3r@gmail.com

If you find a *bug* please open an issue and include at least the following in the description:

- Full command string you used
- OS your using

Also remember: Github markdown is your friend!

How to install on Kali
======================

```apt-get install mitmf```
