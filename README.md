DNSSEC Rollover Tool
====================

This DNSSEC rollover tools helps with ZSK + KSK key rollovers for BIND
operations.

Rudimentary help is available by calling dnssec_rollover_tool --help

Example usage in crontab:

./dnssec_rollover_tool.py -d /xxxx/xxx.net.external.keys/ -n xxx.net -k 15552000 432000 -e xxx@xxx.net xxx@xxx.net -z 2592000 432000 --owner named

