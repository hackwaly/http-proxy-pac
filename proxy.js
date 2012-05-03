var http = require('http');
var https = require('https');
var net = require('net');
var $url = require('url');
var fs = require('fs');
var dns = require('dns');

function parseHostAndPort(url){
    var urlInfo = $url.parse(url);
    return {
        host: urlInfo.hostname,
        port: urlInfo.port
    };
}

http.get({
    host: 'your.pac.domain',
    port: 80,
    path: '/proxy.pac'
}, function (res){
    var buff = [];
    res.on('data', function (chunk){
        buff.push(chunk);
    });
    res.on('end', function (){
        pacGot(buff.join(''));
    });
});

var fnPac;
function pacGot(code){
    fnPac = new Function('dnsResolve', 'shExpMatch', 'isInNet',
        code + ';return FindProxyForURL;')(dnsResolve, shExpMatch, isInNet);
}
// 这里懒得去找通用的了, 胡乱写了个.
function Deferred(){
    this._callbacks = [];
}
Deferred.prototype = {
    then: function (callback){
        this._callbacks.push(callback);
    },
    done: function (value){
        var callback;
        while (callback = this._callbacks.shift()) {
            callback(value);
        }
    }
};
var dnsCache = {};
var dnsDfds = {};
function dnsResolve(host){
    if (!dnsCache[host]) {
        if (!dnsDfds[host]) {
            dnsDfds[host] = new Deferred();
            dns.resolve(host, function (err, address){
                dnsCache[host] = err ? '127.0.0.1' : address[0];
                dnsDfds[host].done(dnsCache[host]);
            });
        }
        throw dnsDfds[host];
    }
    return dnsCache[host];
}
function isPlainHostName(host) {
    return (host.search('\\.') == -1);
}
function isResolvable(host) {
    var ip = dnsResolve(host);
    return (ip != 'null');
}
function localHostOrDomainIs(host, hostdom) {
    return (host == hostdom) ||
        (hostdom.lastIndexOf(host + '.', 0) == 0);
}
function shExpMatch(text, exp){
    exp = exp.replace(/\.|\*|\?/g, function (m){
        if (m === '.') {
            return '\\.';
        } else if (m === '*') {
            return '.*?'
        } else if (m === '?') {
            return '.';
        }
    });
    return new RegExp(exp).test(text);
}
function dnsDomainIs(host, domain) {
    return (host.length >= domain.length &&
        host.substring(host.length - domain.length) == domain);
}
function dnsDomainLevels(host) {
    return host.split('.').length-1;
}
function convert_addr(ipchars) {
    var bytes = ipchars.split('.');
    return ((bytes[0] & 0xff) << 24) |
        ((bytes[1] & 0xff) << 16) |
        ((bytes[2] & 0xff) <<  8) |
        (bytes[3] & 0xff);
}
function isInNet(ipaddr, pattern, maskstr) {
    var test = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ipaddr);
    if (test[1] > 255 || test[2] > 255 ||
        test[3] > 255 || test[4] > 255) {
        return false;    // not an IP address
    }
    var host = convert_addr(ipaddr);
    var pat  = convert_addr(pattern);
    var mask = convert_addr(maskstr);
    return ((host & mask) == (pat & mask));
}
function pac(url, callback){
    var hostAndPort = parseHostAndPort(url);
    function tryPac(){
        try {
            callback(fnPac(url, hostAndPort.host));
        } catch(ex) {
            if (ex instanceof Deferred) {
                ex.then(tryPac);
            } else {
                throw ex;
            }
        }
    }
    tryPac();
}
function getProxyHostAndPort(url, callback){
    var hostAndPort = parseHostAndPort(url);
    var isHttps = url.indexOf('https:') !== -1;
    if (!fnPac) {
        callback(hostAndPort);
    } else {
        pac(url, function (str){
            var p = str.split(/\s*;\s*/g)[0];
            if (p.indexOf('PROXY') !== -1) {
                var m = /PROXY\s*([^:]+)(?::(\d+))?/.exec(p);
                callback({
                    host: m[1],
                    port: !isHttps ? Number(m[2]) || 8080 : 443
                });
            } else {
                callback(hostAndPort);
            }
        });
    }
}
net.createServer(function (clientSocket){
    clientSocket.once('data', function (chunk){
        console.log(chunk.toString());
        // 解析http协议头
        var url = /[A-Z]+\s+([^\s]+)\s+HTTP/.exec(chunk)[1];
        if (url.indexOf('//') === -1) {
            // https协议交给pac脚本会得到错误的端口.
            url = 'http://' + url;
        }
        getProxyHostAndPort(url, function (hostAndPort){
            var serverSocket = net.connect(hostAndPort.port, hostAndPort.host, function() {
                clientSocket.pipe(serverSocket);
                serverSocket.write(chunk);
                serverSocket.pipe(clientSocket);
                serverSocket.on('end', function() {
                    clientSocket.end();
                });
            });
        });
    });
}).listen(8088);
