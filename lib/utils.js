// Load modules

var Hoek = require('hoek');
var Sntp = require('sntp');


// Declare internals

var internals = {};


// Import Hoek Utilities

internals.import = function () {

    for (var i in Hoek) {
        if (Hoek.hasOwnProperty(i)) {
            exports[i] = Hoek[i];
        }
    }
};

internals.import();


// Hawk version

exports.version = function () {

    return exports.loadPackage(__dirname + '/..').version;
};


// Extract host and port from request

exports.parseHost = function (req, hostHeaderName) {

    hostHeaderName = (hostHeaderName ? hostHeaderName.toLowerCase() : 'host');
    var hostHeader = req.headers[hostHeaderName];
    if (!hostHeader) {
        return null;
    }

    var hostHeaderRegex = /^(?:(?:\r\n)?[\t ])*([^:]+)(?::(\d+))?(?:(?:\r\n)?[\t ])*$/;     // Does not support IPv6
    var hostParts = hostHeader.match(hostHeaderRegex);

    if (!hostParts ||
        hostParts.length !== 3 ||
        !hostParts[1]) {

        return null;
    }

    return {
        name: hostParts[1],
        port: (hostParts[2] ? hostParts[2] : (req.connection && req.connection.encrypted ? 443 : 80))
    };
};


// Convert node's  to request configuration object

exports.parseRequest = function (req, options) {

    if (!req.headers) {
        return req;
    }

    // Obtain host and port information

    var host = exports.parseHost(req, options.hostHeaderName);
    if (!host) {
        return new Error('Invalid Host header');
    }

    var req = {
        method: req.method,
        url: req.url,
        host: host.name,
        port: host.port,
        authorization: req.headers.authorization
    };

    return req;
};


exports.now = function () {

    return Sntp.now();
};

