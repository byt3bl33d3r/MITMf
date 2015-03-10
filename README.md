MITMf V0.9.5
============

Framework for Man-In-The-Middle attacks

Quick tutorials, examples and dev updates at http://sign0f4.blogspot.it

This tool is completely based on sergio-proxy https://code.google.com/p/sergio-proxy/ and is an attempt to revive and update the project.

Availible plugins:
- Responder - LLMNR, NBT-NS and MDNS poisoner
- SSLstrip+ - Partially bypass HSTS
- Spoof - Redirect traffic using ARP Spoofing, ICMP Redirects or DHCP Spoofing and modify DNS queries
- Sniffer - Sniffs for various protocol login and auth attempts
- BeEFAutorun - Autoruns BeEF modules based on clients OS or browser type
- AppCachePoison - Perform app cache poison attacks 
- SessionHijacking - Performs session hijacking attacks, and stores cookies in a firefox profile
- BrowserProfiler - Attempts to enumerate all browser plugins of connected clients
- CacheKill - Kills page caching by modifying headers
- FilePwn - Backdoor executables being sent over http using bdfactory
- Inject - Inject arbitrary content into HTML content
- JavaPwn - Performs drive-by attacks on clients with out-of-date java browser plugins
- jskeylogger - Injects a javascript keylogger into clients webpages
- Replace - Replace arbitary content in HTML content
- SMBAuth - Evoke SMB challenge-response auth attempts
- Upsidedownternet - Flips images 180 degrees

So far the most significant changes have been:

- Addition of the Sniffer plugin which integrates Net-Creds (https://github.com/DanMcInerney/net-creds) currently supported protocols are:
  FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc..) and Kerberos

- Integrated Responder (https://github.com/SpiderLabs/Responder) to poison LLMNR, NBT-NS and MDNS, and act as a WPAD rogue server.

- Integrated SSLstrip+ (https://github.com/LeonardoNve/sslstrip2) by Leonardo Nve to partially bypass HSTS as demonstrated at BlackHat Asia 2014 

- Addition of the SessionHijacking plugin, which uses code from FireLamb (https://github.com/sensepost/mana/tree/master/firelamb) to store cookies in a Firefox profile 

- Spoof plugin now supports ICMP, ARP and DHCP spoofing along with DNS tampering

- Spoof plugin can now exploit the 'ShellShock' bug when DHCP spoofing! 

- Usage of third party tools has been completely removed (e.g. ettercap)

- FilePwn plugin re-written to backdoor executables and zip files on the fly by using the-backdoor-factory
https://github.com/secretsquirrel/the-backdoor-factory and code from BDFProxy https://github.com/secretsquirrel/BDFProxy

- Added msfrpc.py for interfacing with Metasploits rpc server

- Added beefapi.py for interfacing with BeEF's RESTfulAPI

- Addition of the app-cache poisoning attack by Krzysztof Kotowicz

<h3>How to install on Kali</h3>

MITMf is now in tha kali linux repositories!

```apt-get install mitmf```
