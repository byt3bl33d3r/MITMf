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

Additionally, the framework contains a built-in SMB, HTTP and DNS server that can be controlled and used by the various plugins.

Available plugins
=================
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
