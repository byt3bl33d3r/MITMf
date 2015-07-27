- Added active filtering/injection into the framework

- Fixed a bug in the DHCP poisoner which prevented it from working on windows OS's

- Made some preformance improvements to the ARP spoofing poisoner

- Refactored Appcachepoison , BrowserSniper plugins

- Refactored proxy plugin API

-Inject plugin now uses BeautifulSoup4 to parse and inject HTML/JS 

- Added HTA Drive by plugin

- Added the SMBTrap plugin

- Config file now updates on the fly!

- SessionHijacker is replaced with Ferret-NG captures cookies and starts a proxy that will feed them to connected clients

- JavaPwn plugin replaced with BrowserSniper now supports Java, Flash and browser exploits

- Addition of the Screenshotter plugin, able to render screenshots of a client's browser at regular intervals

- Addition of a fully functional SMB server using the [Impacket](https://github.com/CoreSecurity/impacket) library

- Addition of [DNSChef](https://github.com/iphelix/dnschef), the framework is now a IPv4/IPv6 (TCP & UDP) DNS server! Supported queries are: 'A', 'AAAA', 'MX', 'PTR', 'NS', 'CNAME', 'TXT', 'SOA', 'NAPTR', 'SRV', 'DNSKEY' and 'RRSIG'

- Integrated [Net-Creds](https://github.com/DanMcInerney/net-creds) currently supported protocols are: FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc.) and Kerberos

- Integrated [Responder](https://github.com/SpiderLabs/Responder) to poison LLMNR, NBT-NS and MDNS and act as a rogue WPAD server

- Integrated [SSLstrip+](https://github.com/LeonardoNve/sslstrip2) by Leonardo Nve to partially bypass HSTS as demonstrated at BlackHat Asia 2014 

- Spoof plugin can now exploit the 'ShellShock' bug when DHCP spoofing 

- Spoof plugin now supports ICMP, ARP and DHCP spoofing

- Usage of third party tools has been completely removed (e.g. Ettercap)

- FilePwn plugin re-written to backdoor executables zip and tar files on the fly by using [the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory) and code from [BDFProxy](https://github.com/secretsquirrel/BDFProxy)

- Added [msfrpc.py](https://github.com/byt3bl33d3r/msfrpc/blob/master/python-msfrpc/msfrpc.py) for interfacing with Metasploit's RPC server

- Added [beefapi.py](https://github.com/byt3bl33d3r/beefapi) for interfacing with BeEF's RESTfulAPI

- Addition of the app-cache poisoning attack by [Krzysztof Kotowicz](https://github.com/koto/sslstrip) (blogpost explaining the attack here: http://blog.kotowicz.net/2010/12/squid-imposter-phishing-websites.html)