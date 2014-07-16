MITMf
=====

Framework for Man-In-The-Middle attacks

Quick tutorial and examples at http://sign0f4.blogspot.it/2014/07/introducing-mitmf-framework-for-man-in.html

This tool is completely based on sergio-proxy https://code.google.com/p/sergio-proxy/ and is an attempt to revive and update the project.

So far the most significant changes have been:

- Arpspoof plugin has been completely re-written to use scapy (Now able to poison via arp-requests and arp-replies)

- Usage of third party tools has been completely removed (e.g. ettercap)

- Addition of the BrowserProfiler plugin

- Addition of the JsKeylogger plugin

- FilePwn plugin re-written to backdoor executables and zip files on the fly by using the-backdoor-factory        
https://github.com/secretsquirrel/the-backdoor-factory

- Added msfrpc.py for interfacing with Metasploits rpc server

- Addition of the app-cache poisoning attack by Krzysztof Kotowicz 

- JavaPwn plugin now live! Auto-detect and exploit clients with out-of-date java plugins using the Metasploit Frameworks rpc interface!!

Coming Soon:

- Update hijacking ??? (e.g. evilgrade)
