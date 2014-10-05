A Haraka plugin for enforcing email route by hostname
-----------------------------------------------------

This plugin provides a source ip based "authentication" for clients which are not able to authenticate themselves to MTA.

## Motivation
Certain applications (eg. SAP) are not able to send emails with authentication. In this case to avoid setting up open relay one would have to allow mail receipt by source IP. While this option is available even on Microsoft Exchange (restrict mail connector access by source IP), it is not possible to enforce certain sender on the receipt side. That means, (eg.) SAP application server can send email in anyone's name. 

Since email communication within enterprise is highly trusted that is not a good idea: an attacker breaking into SAP application server can impersonate anyone within the domain. Too bad. 

There is two option: elevate SAP server's trust level to that of Active Directory's or create a controlled mail sending facility. This plugin is to solve this problem.

## Example setup

Suppose we have two servers (server1 and server2) both hosting services not able to authenticate against AD. Server1 has to send email with noreply-app@example.com to example.com addresses while server2 has to send emails with nessus@example.com and syslog@example.com mails from to infosec@example.com. The network setup is like this:

    server1 (192.168.100.1) ------+
                                  |----> haraka (192.168.100.200) ----> AD (192.168.10.10)
    server2 (192.168.100.2) ------+

## Configuration

To set up haraka for the example setup you should do the following:
####Create a default haraka setup with 
    haraka -i /path/to/harakatest
####Edit ``config/plugins``
    queue/smtp_proxy
    tls
    enforce_route_by_ip
####Edit ``config/smtp_proxy.ini
    host=192.168.10.10
    port=25
    enable_tls=1
    [auth]
    type=plain
    user=<your Active Directory user name>
    pass=<your password>
####Edit ``config/enforce_route_by_ip.ini``
    [domain]
    192.168.100.1=noreply-app@example.com
    192.168.100.2=nessus@example.com, syslog@example.com

    [rcpt_to]
    noreply-app@example.com=example.com
    nessus@example.com=infosec@example.com
    syslog@example.com=infosec@example.com

By setting ``strict_mode=no`` in ``enforce_route_by_ip.ini`` the plugin will allow email exchanges which are not configured. It is an optional unsafe mode. The strict mode is set to yes be default, of course.

