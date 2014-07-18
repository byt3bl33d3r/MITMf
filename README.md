MITMf
=====

Framework for Man-In-The-Middle attacks

Quick tutorial and examples at http://sign0f4.blogspot.it

This tool is completely based on sergio-proxy https://code.google.com/p/sergio-proxy/ and is an attempt to revive and update the project.

Availible plugins:
- ArpSpoof - Redirect traffic using arp-spoofing
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

- Arpspoof plugin has been completely re-written to use scapy (Now able to poison via arp-requests and arp-replies)

- Usage of third party tools has been completely removed (e.g. ettercap)

- Addition of the BrowserProfiler plugin

- Addition of the JsKeylogger plugin

- FilePwn plugin re-written to backdoor executables and zip files on the fly by using the-backdoor-factory
https://github.com/secretsquirrel/the-backdoor-factory and code from BDFProxy https://github.com/secretsquirrel/BDFProxy

- Added msfrpc.py for interfacing with Metasploits rpc server

- Added Replace plugin

- Addition of the app-cache poisoning attack by Krzysztof Kotowicz 

- JavaPwn plugin now live! Auto-detect and exploit clients with out-of-date java plugins using the Metasploit Frameworks rpc interface!!
