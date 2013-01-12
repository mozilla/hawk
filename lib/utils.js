// Load modules

var Http = require('http');
var Hoek = require('hoek');


// Declare internals

var internals = {
    randomSource: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
};


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


// Generate a random string of given size (not for crypto)

exports.randomString = function (size) {

    var result = [];

    var len = internals.randomSource.length;
    for (var i = 0; i < size; ++i) {
        result.push(internals.randomSource[Math.floor(Math.random() * len)]);
    }

    return result.join('');
};


// Compare two strings using fixed time algorithm (to prevent time-based analysis of MAC digest match)

exports.fixedTimeComparison = function (a, b) {

    var mismatch = (a.length === b.length ? 0 : 1);
    if (mismatch) {
        b = a;
    }

    for (var i = 0, il = a.length; i < il; ++i) {
        var ac = a.charCodeAt(i);
        var bc = b.charCodeAt(i);
        mismatch += (ac === bc ? 0 : 1);
    }

    return (mismatch === 0);
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

    if (req instanceof Http.IncomingMessage == false) {
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

