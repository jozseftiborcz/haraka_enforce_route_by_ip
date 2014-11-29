// enforce_route_by_ip
//
var addr_parser = require("address-rfc2822");

exports.register = function() {
    var plugin = this;

    plugin.cfg = plugin.config.get('enforce_route_by_ip.ini');
    plugin.cfg.open_relay = plugin.cfg.main.open_relay || 'no';
    if (plugin.cfg.open_relay === 'yes') plugin.loginfo(plugin, "Working in open_relay mode");
    if (!plugin.cfg.mail_from) {
        if (plugin.cfg.open_relay !== 'yes') plugin.logerror(plugin, "No source IP is given, every email will be rejected");
        else plugin.logwarn(plugin, "plugin will allow every sender");
    } 
    else {
        exports.load_rules();
    }
};

exports.load_rules = function() {
    var plugin = this;

    plugin.source_ips = {};
    var email_addrs = {};
    var ip;
    Object.keys(plugin.cfg.mail_from).forEach(function(ip) {
        plugin.source_ips[ip] = (plugin.cfg.mail_from[ip] || '').split(',').map(function(val) { 
            return val.trim();
        }).filter(function(email_addr) {
            if (email_addr.toLowerCase() === "any") {
                plugin.loginfo('Every sender is accepted from host ' + ip);
            }
            else if (email_addr.search('@') == -1) {
                plugin.logerror('Host ' +ip + "'s email address " + email_addr + " is not a valid, ignoring");
                return false;
            }
            email_addrs[email_addr] = 1;
            return true;
        });
    })

    plugin.rcpt_to_addrs = {};
    plugin.rcpt_to_domains = {};

    Object.keys(plugin.cfg.rcpt_to).forEach(function(email_addr) {
        if (!email_addrs.hasOwnProperty(email_addr))
            plugin.logwarn('rcpt_to', email_addr + " is missing from mail_from section, skipping");
        else { 
            plugin.rcpt_to_addrs[email_addr] = plugin.cfg.rcpt_to[email_addr].split(',').map(function(val) { 
                return val.trim();
            });

            plugin.rcpt_to_domains[email_addr] = [];
            plugin.rcpt_to_addrs[email_addr] = plugin.rcpt_to_addrs[email_addr].filter(function(addr) {
                if (exports.is_domain(addr)) plugin.rcpt_to_domains[email_addr].push(addr);
                return !exports.is_domain(addr);
            });
            delete email_addrs[email_addr];
        }
    });
    for (var email_addr in email_addrs) {
        plugin.loginfo(email_addr + ' can send to any address');
    }
};

exports.is_domain = function(email_addr) {
    return email_addr.indexOf('@')==-1;
};

exports.get_domain = function(email_addr) {
    return addr_parser.parse(email_addr)[0].host();
};

exports.hook_connect = function(next, connection) {
    var plugin = this;
    var ip = connection.remote_ip;

    if (!plugin.source_ips[ip] && plugin.cfg.open_relay !== 'yes') {
        next(DENY,ip + ' is not authorized');
        plugin.logerror(ip + ' is not authorized');
    }
    else {
        next();
    }
};

exports.allowed_rcpt_to = function(mail_from, rcpt) {
    var plugin = this;
    return mail_from in plugin.rcpt_to_addrs 
        && plugin.rcpt_to_addrs[mail_from].indexOf(rcpt) !== -1;
};

exports.allowed_rcpt_domain = function(mail_from, rcpt) {
    var plugin = this;
    return mail_from in plugin.rcpt_to_domains && 
        plugin.rcpt_to_domains[mail_from].indexOf(exports.get_domain(rcpt)) !== -1;
};

exports.hook_rcpt = function(next, connection, to) {
    if (exports.validate_rcpt(next, connection, to[0].address())) next(OK);
};

exports.validate_mail = function(next, connection, addr) {
    var plugin = this;
    var ip = connection.remote_ip;

    if (plugin.source_ips[ip] && plugin.source_ips[ip].indexOf("any")==-1 && plugin.source_ips[ip].indexOf(addr)==-1) {
        next(DENY, addr + " is not allowed sender at " + ip);
        plugin.logerror(addr + " is not allowed sender at " + ip);
        return false;
    }
    return true;
};

exports.hook_mail = function(next, connection, from) {
    if (exports.validate_mail(next, connection, from[0].address())) next(OK); 
};

exports.hook_data_post = function(next, connection) {
    var plugin = this;
    var result = true;

    ['From', 'Sender'].forEach(function(key) {
        if (!result) return;
        var values = connection.transaction.header.get_all(key);
        values.forEach(function(value) {
            addr_parser.parse(value).forEach(function(addr) {
                if (addr.address.toLowerCase() !== connection.transaction.mail_from.original.toLowerCase()) {
                    plugin.logerror(key + " field's value is not equal with envelope's value");
                    next(DENY, key + " field's value is not equal with envelope's value");
                    result = false;
                }
            });
        });
    });
    if (!result) return;
    addr_parser.parse(connection.transaction.header.get_all("CC")).forEach(function(addr) {
        result = result && exports.validat_rcpt(next, connection, addr);
    });
    if (result) next(OK);
};

exports.validate_rcpt = function(next, connection, addr) {
    var plugin = this;
    var ip = connection.remote_ip;
    var mail_from = connection.transaction.mail_from.original;

    if (exports.allowed_rcpt_to(mail_from, addr) || exports.allowed_rcpt_domain(mail_from, addr)) {
        return true;
    }
    if (plugin.cfg.open_relay!=='yes' && plugin.source_ips[ip].indexOf('any')==-1) {
        plugin.logerror(addr + " is not allowed recepient at " + ip);
        next(DENY, addr + " is not allowed recepient at " + ip);
        return false;
    }
    return true;
};

