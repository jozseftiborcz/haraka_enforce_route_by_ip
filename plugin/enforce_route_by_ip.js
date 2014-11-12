// enforce_route_by_ip
//
exports.register = function() {
    var plugin = this;

    plugin.cfg = plugin.config.get('enforce_route_by_ip.ini');
    plugin.cfg.strict_mode = plugin.cfg.main.strict_mode || 'yes';
    if (!plugin.cfg.domain) {
        if (plugin.cfg.strict_mode === 'yes') plugin.logerror(plugin, "No source IP is given, every email will be rejected");
        else plugin.logwarn(plugin, "No source IP is given, plugin can be removed");
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
    Object.keys(plugin.cfg.domain).forEach(function(ip) {
        plugin.source_ips[ip] = (plugin.cfg.domain[ip] || '').split(',').map(function(val) { 
            return val.trim();
        }).filter(function(email_addr) {
            if (email_addr.search('@') == -1) {
                plugin.logerror('Host ' +ip + "'s email address " + email_addr + " is not a valid, ignoring");
                return false;
            }
            email_addrs[email_addr] = 1;
            return true;
        });
    })

    plugin.rcpt_to_addrs = {};
    plugin.rcpt_to_domains = {};
    var email_addr;
    Object.keys(plugin.cfg.rcpt_to).forEach(function(email_addr) {
        if (!email_addrs.hasOwnProperty(email_addr))
            plugin.logwarn('rcpt_to', email_addr + " is missing from domain definition, skipping");
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
    for (email_addr in email_addrs) {
        plugin.logdebug(email_addr + ' can send to any address');
    }
};

exports.is_domain = function(email_addr) {
    return email_addr.indexOf('@')==-1;
};

exports.get_domain = function(email_addr) {
    return email_addr.replace(/.*@/,"");
};

exports.hook_connect = function(next, connection) {
    var plugin = this;
    var ip = connection.remote_ip;

    if (!plugin.source_ips[ip] && plugin.strict_mode==='yes') {
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
    var plugin = this;
    var addr = to[0].address();
    var ip = connection.remote_ip;
    var mail_from = connection.transaction.mail_from.original;

    if (exports.allowed_rcpt_to(mail_from, addr) || exports.allowed_rcpt_domain(mail_from, addr)) {
        next(OK);
        return;
    }
    if (plugin.strict_mode!=='yes') {
        plugin.logerror(addr + " is not allowed recepient at " + ip);
        next(DENY, addr + " is not allowed recepient at " + ip);
    }
    else {
        next(OK);
    }
};

exports.hook_mail = function(next, connection, from) {
    var plugin = this;
    var ip = connection.remote_ip;
    var addr = from[0].address();

    if (plugin.source_ips[ip] && plugin.source_ips[ip].indexOf(addr)==-1) {
        next(DENY, addr + " is not allowed sender at " + ip);
        plugin.logerror(addr + " is not allowed sender at " + ip);
    }
    else {
        next();
    }
};

