A Haraka plugin for enforcing email route by hostname
-----------------------------------------------------

This plugin provides a source ip based "authentication" for clients which are not able to authenticate themselves to MTA.

Motivation
==========
Certain applications (eg. SAP) are not able to send emails with authentication. In this case to avoid setting up open relay one would have to allow mail receipt by source IP. While this option is available even on Microsoft Exchange (restrict mail connector access by source IP), it is not possible to enforce certain sender on the receipt side. That means, (eg.) SAP application server can send email in anyone's name. 

Since email communication within enterprise is highly trusted that is not a good idea: an attacker breaking into SAP application server can impersonate anyone within the domain. Too bad. 

There is two option: elevate SAP server's trust level to that of Active Directory's or create a controlled mail sending facility. This plugin is to solve this problem.

Example setup
=============

Suppose we have two servers (server1 and server2) both hosting services not able to authenticate against AD. Server1 has to send email with noreply-app@example.com to example.com addresses while server2 has to send emails with nessus@example.com and syslog@example.com mails from to infosec@example.com. The network setup is like this:

 server1 (192.168.100.1) ------+
                               |----> haraka (192.168.100.200) ----> AD (192.168.10.10)
 server2 (192.168.100.2) ------+

Configuration
=============

