![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
![Latest Version](https://img.shields.io/badge/mitmf-0.9.8%20--%20The%20Dark%20Side-red.svg)

#MITMf

Framework for Man-In-The-Middle attacks

Quick tutorials, examples and developer updates at: https://byt3bl33d3r.github.io

This tool is based on [sergio-proxy](https://github.com/supernothing/sergio-proxy) and is an attempt to revive and update the project.

Contact me at:
- Twitter: @byt3bl33d3r
- IRC on Freenode: #MITMf
- Email: byt3bl33d3r@gmail.com

**Before submitting issues, please read the [FAQ](#faq) and [CONTRIBUTING.md](CONTRIBUTING.md).**

Available plugins
=================
- ```HTA Drive-By```     : Injects a fake update notification and prompts clients to download an HTA application
- ```SMBtrap```          : Exploits the 'SMB Trap' vulnerability on connected clients
- ```Screenshotter```    : Uses HTML5 Canvas to render an accurate screenshot of a clients browser
- ```Responder```        : LLMNR, NBT-NS, WPAD and MDNS poisoner
- ```SSLstrip+```        : Partially bypass HSTS
- ```Spoof```            : Redirect traffic using ARP spoofing, ICMP redirects or DHCP spoofing
- ```BeEFAutorun```      : Autoruns BeEF modules based on a client's OS or browser type
- ```AppCachePoison```   : Perform app cache poisoning attacks 
- ```Ferret-NG```        : Transperently hijacks sessions
- ```BrowserProfiler```  : Attempts to enumerate all browser plugins of connected clients
- ```FilePwn```          : Backdoor executables sent over HTTP using the Backdoor Factory and BDFProxy
- ```Inject```           : Inject arbitrary content into HTML content
- ```BrowserSniper```    : Performs drive-by attacks on clients with out-of-date browser plugins
- ```jskeylogger```      : Injects a Javascript keylogger into a client's webpages
- ```Replace```          : Replace arbitary content in HTML content
- ```SMBAuth```          : Evoke SMB challenge-response authentication attempts
- ```Upsidedownternet``` : Flips images 180 degrees

How to install on Kali
======================

```apt-get install mitmf```

**Currently Kali has a very old version of MITMf in its repos, read the [Installation](#installation) section to get the latest version**

Installation
============
If you're rocking Kali and want the latest version:
- Clone this repository
- Run the ```kali_setup.sh``` script

**Note: you can ignore any errors when ```pip``` tries to install dependencies, MITMf should be able to run anyway**

If you're rocking any other Linux distro:
- Clone this repository
- Run the ```other_setup.sh``` script
- Run the command ```pip install --upgrade mitmflib``` to install all Python dependencies

FAQ
===
- **Is Windows supported?**
- No, it will never be supported (so don't ask).

- **Is OSX supported?**
- Yes! Initial compatibility has been introduced in 0.9.8! Find anything broken submit a PR or open an issue ticket!

- **I can't install package X because of an error!**
- Try installing the package via ```pip``` or your distro's package manager. This *isn't* a problem with MITMf.

- **How do I install package X?**
- Please read the [installation](#installation) guide.

- **I get an ImportError when launching MITMf!**
- Please read the [installation](#installation) guide.

- **Dude, no documentation?**
- The docs are a work in progress at the moment, once the framework hits 1.0 I will push them to the wiki