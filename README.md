MITMf
=====

Framework for Man-In-The-Middle attacks

This tool is completely based on sergio-proxy https://code.google.com/p/sergio-proxy/ and is an attempt to revive and update the project.

So far the most significant changes have been:

- Arpspoof plugin has been completly re-written to use scapy instead of third-party tools (e.g. ettercao)

- Addition of the BrowserProfiler plugin

- Addition of the app-cache poisoning attack by Krzysztof Kotowicz 

Coming Soon:

- JavascriptKeylogger plugin
- FilePwn plugin revamp by integrating bdfproxy https://github.com/secretsquirrel/BDFProxy
- MSFrpc support would be awesome
