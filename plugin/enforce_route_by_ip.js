// enforce_route_by_ip

// documentation via: haraka -c /home/joe/work/haraka_test -h plugins/enforce_route_by_ip

// Put your plugin code here
// type: `haraka -h Plugins` for documentation on how to create a plugin

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

    plugin.rcpt_tos = {};
    var email_addr;
    Object.keys(plugin.cfg.rcpt_to).forEach(function(email_addr) {
        if (!email_addrs.hasOwnProperty(email_addr))
            plugin.logwarn('rcpt_to', email_addr + " is missing from domain definition, skipping");
        else { 
            plugin.rcpt_tos[email_addr] = plugin.cfg.rcpt_to[email_addr].split(',').map(function(val) { 
                return val.trim();
            });
            delete email_addrs[email_addr];
        }
    });
    for (email_addr in email_addrs) {
        plugin.logdebug(email_addr + ' can send to any address');
    }
};

exports.hook_connect = function(next, connection) {
    var plugin = this;

    if (!plugin.source_ips[connection.remote_ip]) {
        next(DENY,connection.remote_ip + ' is not authorized');
        plugin.logerror(connection.remote_ip + ' is not authorized');
    }
    else {
        next();
    }
};

exports.hook_rcpt = function(next, connection, to) {
    var plugin = this;

    if (plugin.rcpt_tos[connection.remote_ip].indexOf(to[0].address())==-1) {
        next(DENY, to[0].address() + " is not allowed recepient " + connection.remote_ip);
        plugin.logerror(to[0].address() + " is not allowed recepient " + connection.remote_ip);
        return;
    }
    next(OK);
};

exports.hook_mail = function(next, connection, from) {
    var plugin = this;

    if (plugin.source_ips[connection.remote_ip].indexOf(from[0].address())==-1) {
        next(DENY, from[0].address() + " is not allowed from " + connection.remote_ip);
        plugin.logerror(from[0].address() + " is not allowed from " + connection.remote_ip);
        return;
    }
    next();
};
