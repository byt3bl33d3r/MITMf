MITMf V0.9.7
============

Framework for Man-In-The-Middle attacks

Quick tutorials, examples and developer updates at: https://byt3bl33d3r.github.io

This tool is based on [sergio-proxy](https://github.com/supernothing/sergio-proxy) and is an attempt to revive and update the project.

Contact me at:
- Twitter: @byt3bl33d3r
- IRC on Freenode: #MITMf
- Email: byt3bl33d3r@gmail.com

**Update: Installation steps have changed! Please read the new [instructions](#installation)** 

**Before submitting issues, please read the [FAQ](#faq) and the appropriate [section](#submitting-issues).**

Available plugins
=================
- ```SMBtrap``` - Exploits the 'SMB Trap' vulnerability on connected clients
- ```Screenshotter``` -  Uses HTML5 Canvas to render an accurate screenshot of a clients browser
- ```Responder``` - LLMNR, NBT-NS, WPAD and MDNS poisoner
- ```SSLstrip+``` - Partially bypass HSTS
- ```Spoof``` - Redirect traffic using ARP spoofing, ICMP redirects or DHCP spoofing
- ```BeEFAutorun``` - Autoruns BeEF modules based on a client's OS or browser type
- ```AppCachePoison``` - Perform app cache poisoning attacks 
- ```Ferret-NG``` - Transperently hijacks sessions
- ```BrowserProfiler``` - Attempts to enumerate all browser plugins of connected clients
- ```CacheKill``` - Kills page caching by modifying headers
- ```FilePwn``` - Backdoor executables sent over HTTP using the Backdoor Factory and BDFProxy
- ```Inject``` - Inject arbitrary content into HTML content
- ```BrowserSniper``` - Performs drive-by attacks on clients with out-of-date browser plugins
- ```jskeylogger``` - Injects a Javascript keylogger into a client's webpages
- ```Replace``` - Replace arbitary content in HTML content
- ```SMBAuth``` - Evoke SMB challenge-response authentication attempts
- ```Upsidedownternet``` - Flips images 180 degrees

Changelog
=========

- Added the ```SMBTrap``` plugin

- Config file now updates on the fly!

- ```SessionHijacker``` is replaced with ```Ferret-NG```,  captures cookies and starts a proxy that will feed them to connected clients

- ```JavaPwn``` plugin replced with ```BrowserSniper```, now supports Java, Flash and browser exploits

- Addition of the ```Screenshotter``` plugin, able to render screenshots of a client's browser at regular intervals

- Addition of a fully functional SMB server using the [Impacket](https://github.com/CoreSecurity/impacket) library

- Addition of [DNSChef](https://github.com/iphelix/dnschef), the framework is now a IPv4/IPv6 (TCP & UDP) DNS server! Supported queries are: 'A', 'AAAA', 'MX', 'PTR', 'NS', 'CNAME', 'TXT', 'SOA', 'NAPTR', 'SRV', 'DNSKEY' and 'RRSIG'

- Integrated [Net-Creds](https://github.com/DanMcInerney/net-creds) currently supported protocols are:
  FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc.) and Kerberos

- Integrated [Responder](https://github.com/SpiderLabs/Responder) to poison LLMNR, NBT-NS and MDNS and act as a rogue WPAD server

- Integrated [SSLstrip+](https://github.com/LeonardoNve/sslstrip2) by Leonardo Nve to partially bypass HSTS as demonstrated at BlackHat Asia 2014 

- ```Spoof``` plugin can now exploit the 'ShellShock' bug when DHCP spoofing 

- ```Spoof``` plugin now supports ICMP, ARP and DHCP spoofing

- Usage of third party tools has been completely removed (e.g. Ettercap)

- ```FilePwn```plugin re-written to backdoor executables zip and tar files on the fly by using [the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory) and code from [BDFProxy](https://github.com/secretsquirrel/BDFProxy)

- Added [msfrpc.py](https://github.com/byt3bl33d3r/msfrpc/blob/master/python-msfrpc/msfrpc.py) for interfacing with Metasploit's RPC server

- Added [beefapi.py](https://github.com/byt3bl33d3r/beefapi) for interfacing with BeEF's RESTfulAPI

- Addition of the app-cache poisoning attack by [Krzysztof Kotowicz](https://github.com/koto/sslstrip) (blogpost explaining the attack here: http://blog.kotowicz.net/2010/12/squid-imposter-phishing-websites.html)

How to install on Kali
======================

```apt-get install mitmf```

**Currently Kali has a very old version of MITMf in its repos, read the [Installation](#installation) section to get the latest version**

Installation
============
If you're rocking Kali and want the latest version:
- Clone this repository
- Run the ```kali_setup.sh``` script

If you're rocking any other Linux distro:
- Clone this repository
- Run the ```other_setup.sh``` script
- Run the command ```pip install --upgrade -r requirements.txt``` to install all Python dependencies

Submitting Issues
=================
If you have *questions* regarding the framework please email me at byt3bl33d3r@gmail.com

**Only submit issues if you find a bug in the latest version of the framework.**

When inevitably you do come across said *bug*, please open an issue and include at least the following in the description:

- Full command string you used
- OS you're using
- Full error traceback, if any

Also, remember that Github markdown is your friend!

FAQ
===
- **Is Windows supported?**
- No

- **Is OSX supported?**
- Currently no, although with some tweaking (which I'll probably get around to in the near future), it should be able to run perfectly on OSX.

- **I can't install package X because of an error!**
- Try installing the package via ```pip``` or your distro's package manager. This *isn't* a problem with MITMf.

- **How do I install package X?**
- Please read the [installation](#installation) guide.

- **I get an ImportError when launching MITMf!**
- Please read the [installation](#installation) guide.

- **Dude, no documentation/video tutorials?**
- Currently no but once the framework hits 1.0, I'll probably start writing/making some.
